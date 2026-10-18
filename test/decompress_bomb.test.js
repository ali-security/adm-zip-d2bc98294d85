"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");
const Utils = require("../util");
const Constants = Utils.Constants;

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Same crafted archive as craftBomb, but carrying the genuine CRC-32 of `uncompressed`
// in both headers, so the entry is valid in every respect except its lying size field.
function craftLyingArchive(declaredSize, method, content, uncompressed) {
    const buf = craftBomb(declaredSize, method, content);
    const crc = Utils.crc32(uncompressed);
    const cenOffset = buf.readUInt32LE(buf.length - Constants.ENDHDR + Constants.ENDOFF);
    buf.writeUInt32LE(crc, Constants.LOCCRC);
    buf.writeUInt32LE(crc, cenOffset + Constants.CENCRC);
    return buf;
}

describe("decompression bomb (declared size) - CVE-2026-39244 - allocation guard", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB declared by a few hundred bytes of archive
    // the largest single Buffer.alloc reading such a tiny archive may legitimately need
    const ALLOC_LIMIT = 64 * 1024 * 1024;
    const payload = Buffer.from("hello world ".repeat(64));
    let originalAlloc;
    let largestAlloc;

    // Record every Buffer.alloc made while the entry is read and refuse any request above
    // ALLOC_LIMIT, so allocating the declared size up front fails the test deterministically
    // instead of depending on how much memory the machine running it happens to have.
    beforeEach(() => {
        originalAlloc = Buffer.alloc;
        largestAlloc = 0;
        Buffer.alloc = function (size) {
            if (size > largestAlloc) largestAlloc = size;
            if (size > ALLOC_LIMIT) {
                throw new RangeError("refused oversized Buffer.alloc(" + size + ")");
            }
            return originalAlloc.apply(Buffer, arguments);
        };
    });

    afterEach(() => {
        Buffer.alloc = originalAlloc;
    });

    const storedEntry = () => new Zip(craftLyingArchive(DECLARED, Constants.STORED, payload, payload)).getEntries()[0];
    const deflatedEntry = () => new Zip(craftLyingArchive(DECLARED, Constants.DEFLATED, zlib.deflateRawSync(payload), payload)).getEntries()[0];

    // runs the assertions inside an async callback and reports the outcome to mocha
    const settle = (done, check) => (data, err) => {
        try {
            check(data, err);
            done();
        } catch (e) {
            done(e);
        }
    };

    it("getData() on a STORED entry allocates from the stored bytes, not the declared size", () => {
        const entry = storedEntry();
        expect(entry.header.size).to.equal(DECLARED);
        const data = entry.getData();
        expect(data.equals(payload)).to.equal(true);
        expect(largestAlloc).to.be.at.most(ALLOC_LIMIT);
    });

    it("getData() on a DEFLATED entry does not pre-allocate the declared size", () => {
        const entry = deflatedEntry();
        expect(entry.header.size).to.equal(DECLARED);
        const data = entry.getData();
        expect(data.equals(payload)).to.equal(true);
        expect(largestAlloc).to.be.at.most(ALLOC_LIMIT);
    });

    it("getDataAsync() on a STORED entry allocates from the stored bytes, not the declared size", (done) => {
        storedEntry().getDataAsync(
            settle(done, (data, err) => {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                expect(largestAlloc).to.be.at.most(ALLOC_LIMIT);
            })
        );
    });

    it("getDataAsync() on a DEFLATED entry does not pre-allocate the declared size", (done) => {
        deflatedEntry().getDataAsync(
            settle(done, (data, err) => {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                expect(largestAlloc).to.be.at.most(ALLOC_LIMIT);
            })
        );
    });

    it("readFile() and readAsText() do not pre-allocate the declared size", () => {
        const zip = new Zip(craftLyingArchive(DECLARED, Constants.DEFLATED, zlib.deflateRawSync(payload), payload));
        expect(zip.readFile("a").equals(payload)).to.equal(true);
        expect(zip.readAsText("a")).to.equal(payload.toString());
        expect(largestAlloc).to.be.at.most(ALLOC_LIMIT);
    });
});
