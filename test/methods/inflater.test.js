const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../../adm-zip");
const Inflater = require("../../methods/inflater");
const Constants = require("../../util/constants");

// zlib only honours maxOutputLength on the synchronous API from Node 15 onwards (see methods/inflater.js)
const nodeMajor = +process.versions.node.split(".")[0];
const syncCapSupported = nodeMajor >= 15;

// 4 MiB of zeros deflates to a few KiB (~1000:1), a small stand-in for a real decompression bomb
const BOMB_SIZE = 4 * 1024 * 1024;
const SIZE_CAP_MESSAGE = /exceeds the declared uncompressed size/;

function signature(sig) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(sig, 0);
    return buf;
}

// Builds a single-entry DEFLATE archive and, when given, rewrites the uncompressed size declared
// in both the local and the central header (the CRC and compressed data are left untouched).
function craftArchive(content, declaredSize) {
    const zip = new Zip();
    zip.addFile("bomb.bin", content);
    const buf = zip.toBuffer();
    const loc = buf.indexOf(signature(Constants.LOCSIG));
    const cen = buf.indexOf(signature(Constants.CENSIG));
    expect(loc).to.equal(0);
    expect(cen).to.be.greaterThan(loc);
    if (typeof declaredSize === "number") {
        buf.writeUInt32LE(declaredSize, loc + Constants.LOCLEN);
        buf.writeUInt32LE(declaredSize, cen + Constants.CENLEN);
    }
    return buf;
}

function getBombEntry(declaredSize) {
    const zip = new Zip(craftArchive(Buffer.alloc(BOMB_SIZE), declaredSize));
    const entry = zip.getEntry("bomb.bin");
    expect(entry).to.not.equal(null);
    expect(entry.header.method).to.equal(Constants.DEFLATED);
    expect(entry.header.size).to.equal(declaredSize);
    return { zip, entry };
}

// asserts the callback fires exactly once and hands over its arguments
function onceCallback(done, check) {
    let calls = 0;
    return function (data, err) {
        calls++;
        if (calls > 1) return done(new Error("callback invoked more than once"));
        try {
            check(data, err);
        } catch (e) {
            return done(e);
        }
        setTimeout(() => done(calls === 1 ? undefined : new Error("callback invoked more than once")), 50);
    };
}

describe("inflater - decompression size cap", () => {
    const bomb = zlib.deflateRawSync(Buffer.alloc(BOMB_SIZE));

    describe("methods/inflater.js", () => {
        it("bomb compresses well enough to be meaningful", () => {
            expect(bomb.length).to.be.below(BOMB_SIZE / 100);
        });

        it("inflate() refuses to expand past a declared size of 0", function () {
            if (!syncCapSupported) this.skip();
            let error;
            try {
                Inflater(bomb, 0).inflate();
            } catch (e) {
                error = e;
            }
            expect(error, "inflate() must not decompress the bomb").to.be.instanceOf(RangeError);
            expect(error.code).to.equal("ERR_BUFFER_TOO_LARGE");
        });

        it("inflate() refuses to expand past a declared size smaller than the real size", function () {
            if (!syncCapSupported) this.skip();
            expect(() => Inflater(bomb, 1024).inflate()).to.throw(RangeError);
        });

        it("inflateAsync() refuses to expand past a declared size of 0", (done) => {
            Inflater(bomb, 0).inflateAsync(
                onceCallback(done, (data, err) => {
                    expect(err, "inflateAsync() must report the size cap").to.be.an("error");
                    expect(err.message).to.match(SIZE_CAP_MESSAGE);
                    expect(data.length).to.equal(0);
                })
            );
        });

        it("inflateAsync() refuses to expand past a declared size smaller than the real size", (done) => {
            Inflater(bomb, 1024).inflateAsync(
                onceCallback(done, (data, err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(SIZE_CAP_MESSAGE);
                    expect(data.length).to.equal(0);
                })
            );
        });

        it("a genuinely empty stream with declared size 0 still inflates (sync)", () => {
            const result = Inflater(zlib.deflateRawSync(Buffer.alloc(0)), 0).inflate();
            expect(result.length).to.equal(0);
        });

        it("a genuinely empty stream with declared size 0 still inflates (async)", (done) => {
            Inflater(zlib.deflateRawSync(Buffer.alloc(0)), 0).inflateAsync(
                onceCallback(done, (data, err) => {
                    expect(err).to.equal(undefined);
                    expect(data.length).to.equal(0);
                })
            );
        });

        it("data matching its declared size inflates (sync)", () => {
            const result = Inflater(bomb, BOMB_SIZE).inflate();
            expect(result.length).to.equal(BOMB_SIZE);
        });

        it("data matching its declared size inflates (async)", (done) => {
            Inflater(bomb, BOMB_SIZE).inflateAsync(
                onceCallback(done, (data, err) => {
                    expect(err).to.equal(undefined);
                    expect(data.length).to.equal(BOMB_SIZE);
                })
            );
        });

        it("inflateAsync() reports malformed data through the callback", (done) => {
            // 0xff: final block with the reserved block type 3 -> zlib Z_DATA_ERROR
            Inflater(Buffer.from([0xff, 0xff, 0xff, 0xff]), 16).inflateAsync(
                onceCallback(done, (data, err) => {
                    expect(err).to.be.an("error");
                    expect(data.length).to.equal(0);
                })
            );
        });
    });

    describe("zip entries", () => {
        it("getData() rejects an entry declaring an uncompressed size of 0", function () {
            if (!syncCapSupported) this.skip();
            const { entry } = getBombEntry(0);
            let error;
            try {
                entry.getData();
            } catch (e) {
                error = e;
            }
            // without the cap the whole bomb is inflated and only the CRC check fails afterwards
            expect(error, "getData() must not decompress the bomb").to.be.instanceOf(RangeError);
            expect(error.code).to.equal("ERR_BUFFER_TOO_LARGE");
        });

        it("getDataAsync() rejects an entry declaring an uncompressed size of 0", (done) => {
            const { entry } = getBombEntry(0);
            entry.getDataAsync(
                onceCallback(done, (data, err) => {
                    expect(err, "getDataAsync() must report the size cap").to.be.an("error");
                    expect(err.message).to.match(SIZE_CAP_MESSAGE);
                    expect(data.length).to.equal(0);
                })
            );
        });

        it("getDataAsync() rejects an entry whose declared size is smaller than its real size", (done) => {
            const { entry } = getBombEntry(1);
            entry.getDataAsync(
                onceCallback(done, (data, err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(SIZE_CAP_MESSAGE);
                    expect(data.length).to.equal(0);
                })
            );
        });

        it("readAsTextAsync() surfaces the size cap error", (done) => {
            const { zip } = getBombEntry(0);
            zip.readAsTextAsync(
                "bomb.bin",
                onceCallback(done, (data, err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(SIZE_CAP_MESSAGE);
                    expect(data.length).to.equal(0);
                })
            );
        });

        it("readFileAsync() surfaces the size cap error", (done) => {
            const { zip } = getBombEntry(0);
            zip.readFileAsync(
                "bomb.bin",
                onceCallback(done, (data, err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(SIZE_CAP_MESSAGE);
                    expect(data.length).to.equal(0);
                })
            );
        });

        it("entries with an honest uncompressed size still decompress (sync and async)", (done) => {
            const content = Buffer.alloc(BOMB_SIZE, "a");
            const zip = new Zip(craftArchive(content));
            const entry = zip.getEntry("bomb.bin");
            expect(entry.header.size).to.equal(BOMB_SIZE);
            expect(entry.getData().equals(content)).to.equal(true);
            entry.getDataAsync(
                onceCallback(done, (data, err) => {
                    expect(err).to.equal(undefined);
                    expect(data.equals(content)).to.equal(true);
                })
            );
        });
    });
});
