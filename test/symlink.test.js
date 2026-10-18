"use strict";

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression tests for CVE-2026-76845 (symlink attack during extraction):
// sanitize() only proves that the textual output path stays below the
// extraction root. When a component below the root already exists on disk as a
// symlink (or a Windows junction) pointing elsewhere, open()/mkdir() follow it
// and the archive content lands outside the root. Extraction must refuse to
// write through such links.

const IN_THE_WAY = /file in the way/;

// Create a symlink, falling back to a junction for directories (Windows without
// the symlink privilege). Returns false when the platform refuses both.
function makeLink(target, linkPath, type) {
    try {
        fs.symlinkSync(target, linkPath, type);
        return true;
    } catch (e) {
        if (type !== "dir") return false;
    }
    try {
        fs.symlinkSync(target, linkPath, "junction");
        return true;
    } catch (e) {
        return false;
    }
}

// Build an archive in memory and reload it from its bytes, as an attacker
// supplied zip would be. A `null` value creates a directory entry.
function archive(entries) {
    const zip = new Zip();
    Object.keys(entries).forEach((name) => {
        const data = entries[name];
        zip.addFile(name, data === null ? null : Buffer.from(data));
    });
    return new Zip(zip.toBuffer());
}

function shouldHaveFailed() {
    throw new Error("extraction should have been rejected");
}

describe("adm-zip - symlink guard - CVE-2026-76845", function () {
    let base, root, outside;

    beforeEach(function () {
        base = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        root = pth.join(base, "root");
        outside = pth.join(base, "outside");
        fs.mkdirSync(root);
        fs.mkdirSync(outside);
    });

    afterEach(function () {
        rimraf.sync(base, { disableGlob: true });
    });

    // root/link -> outside
    function linkDir(ctx) {
        if (!makeLink(outside, pth.join(root, "link"), "dir")) ctx.skip();
    }

    // root/victim.txt -> outside/secret.txt
    function linkFile(ctx) {
        fs.writeFileSync(pth.join(outside, "secret.txt"), "original");
        if (!makeLink(pth.join(outside, "secret.txt"), pth.join(root, "victim.txt"), "file")) ctx.skip();
    }

    function readSecret() {
        return fs.readFileSync(pth.join(outside, "secret.txt"), "utf8");
    }

    describe("extractAllTo()", function () {
        it("refuses to write a file through a symlinked directory", function () {
            linkDir(this);
            const zip = archive({ "link/evil.txt": "pwned" });

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.be.false;
        });

        it("refuses to overwrite a file through a symlinked file", function () {
            linkFile(this);
            const zip = archive({ "victim.txt": "pwned" });

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(readSecret()).to.equal("original");
        });

        it("refuses to create a directory through a symlinked directory", function () {
            linkDir(this);
            const zip = archive({ "link/sub/": null });

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "sub"))).to.be.false;
        });

        it("still extracts when the target root itself is reached through a symlink", function () {
            const realRoot = pth.join(base, "real");
            fs.mkdirSync(realRoot);
            const rootLink = pth.join(base, "rootlink");
            if (!makeLink(realRoot, rootLink, "dir")) this.skip();
            const zip = archive({ "a/": null, "a/b.txt": "hello", "c.txt": "world" });

            zip.extractAllTo(rootLink, true);
            expect(fs.readFileSync(pth.join(realRoot, "a", "b.txt"), "utf8")).to.equal("hello");
            expect(fs.readFileSync(pth.join(realRoot, "c.txt"), "utf8")).to.equal("world");
        });

        it("still extracts and overwrites normally inside a symlink-free target", function () {
            const zip = archive({ "a/": null, "a/b/": null, "a/b/c.txt": "nested", "d.txt": "top" });

            zip.extractAllTo(root, true);
            zip.extractAllTo(root, true);
            expect(fs.readFileSync(pth.join(root, "a", "b", "c.txt"), "utf8")).to.equal("nested");
            expect(fs.readFileSync(pth.join(root, "d.txt"), "utf8")).to.equal("top");
        });
    });

    describe("extractEntryTo()", function () {
        it("refuses to write a file entry through a symlinked directory", function () {
            linkDir(this);
            const zip = archive({ "link/evil.txt": "pwned" });

            expect(() => zip.extractEntryTo("link/evil.txt", root, true, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.be.false;
        });

        it("refuses to overwrite a file through a symlinked file", function () {
            linkFile(this);
            const zip = archive({ "dir/victim.txt": "pwned" });

            expect(() => zip.extractEntryTo("dir/victim.txt", root, false, true)).to.throw(IN_THE_WAY);
            expect(readSecret()).to.equal("original");
        });

        it("refuses an outFileName that goes through a symlinked directory", function () {
            linkDir(this);
            const zip = archive({ "a.txt": "pwned" });

            expect(() => zip.extractEntryTo("a.txt", root, false, true, false, "link/evil.txt")).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.be.false;
        });

        it("refuses directory children that go through a symlinked directory", function () {
            linkDir(this);
            const zip = archive({ "link/": null, "link/evil.txt": "pwned" });

            expect(() => zip.extractEntryTo("link/", root, true, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.be.false;
        });

        it("still extracts a file entry into a symlink-free target", function () {
            const zip = archive({ "a/b.txt": "hello" });

            expect(zip.extractEntryTo("a/b.txt", root, true, true)).to.be.true;
            expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("hello");
        });
    });

    describe("extractAllToAsync()", function () {
        it("refuses to write a file through a symlinked directory (callback)", function (done) {
            linkDir(this);
            const zip = archive({ "link/evil.txt": "pwned" });
            let called = false;

            zip.extractAllToAsync(root, true, false, function (err) {
                if (called) return;
                called = true;
                try {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(IN_THE_WAY);
                    expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.be.false;
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("refuses to overwrite a file through a symlinked file (promise)", function () {
            linkFile(this);
            const zip = archive({ "victim.txt": "pwned" });

            return zip.extractAllToAsync(root, true, false).then(shouldHaveFailed, (err) => {
                expect(err.message).to.match(IN_THE_WAY);
                expect(readSecret()).to.equal("original");
            });
        });

        it("refuses to create a directory through a symlinked directory (promise)", function () {
            linkDir(this);
            const zip = archive({ "link/sub/": null });

            return zip.extractAllToAsync(root, true, false).then(shouldHaveFailed, (err) => {
                expect(err.message).to.contain("Unable to create folder");
                expect(fs.existsSync(pth.join(outside, "sub"))).to.be.false;
            });
        });

        it("still extracts into a symlink-free target", function () {
            const zip = archive({ "a/": null, "a/b.txt": "hello", "c.txt": "world" });

            return zip.extractAllToAsync(root, true, false).then(() => {
                expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("hello");
                expect(fs.readFileSync(pth.join(root, "c.txt"), "utf8")).to.equal("world");
            });
        });
    });

    describe("Utils.assertPathSafe()", function () {
        const filetools = new Utils();

        it("throws for a symlinked intermediate component", function () {
            linkDir(this);
            expect(() => filetools.assertPathSafe(root, pth.join(root, "link", "a", "b.txt"))).to.throw(IN_THE_WAY);
        });

        it("throws when the final component is a symlink", function () {
            linkFile(this);
            expect(() => filetools.assertPathSafe(root, pth.join(root, "victim.txt"))).to.throw(IN_THE_WAY);
        });

        it("accepts real directories and paths that do not exist yet", function () {
            fs.mkdirSync(pth.join(root, "real"));
            expect(() => filetools.assertPathSafe(root, pth.join(root, "real", "missing", "x.txt"))).to.not.throw();
            expect(() => filetools.assertPathSafe(root, root)).to.not.throw();
        });

        it("ignores symlinks at or above the root", function () {
            linkDir(this);
            const linkedRoot = pth.join(root, "link");
            expect(() => filetools.assertPathSafe(linkedRoot, pth.join(linkedRoot, "x.txt"))).to.not.throw();
            expect(() => filetools.assertPathSafe(linkedRoot, linkedRoot)).to.not.throw();
        });

        it("leaves paths outside the root to sanitize()", function () {
            linkDir(this);
            expect(() => filetools.assertPathSafe(pth.join(root, "a"), pth.join(root, "link", "x.txt"))).to.not.throw();
        });

        it("is a no-op for a custom fs without lstatSync", function () {
            linkDir(this);
            const custom = new Utils({ fs: { statSync: fs.statSync } });
            expect(() => custom.assertPathSafe(root, pth.join(root, "link", "x.txt"))).to.not.throw();
        });
    });
});
