"use strict";
/**
 * Hashing module for JnxBetaSec.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.Hashing = void 0;
const fs = __importStar(require("fs"));
const crypto = __importStar(require("crypto"));
const util_1 = require("util");
const fsReadFilePromise = (0, util_1.promisify)(fs.readFile);
const fsStatPromise = (0, util_1.promisify)(fs.stat);
class Hashing {
    constructor() {
        this.SUPPORTED_ALGORITHMS = {
            md5: () => crypto.createHash("md5"),
            sha1: () => crypto.createHash("sha1"),
            sha256: () => crypto.createHash("sha256"),
            sha384: () => crypto.createHash("sha384"),
            sha512: () => crypto.createHash("sha512"),
            blake2b512: () => crypto.createHash("blake2b512"),
            blake2s256: () => crypto.createHash("blake2s256"),
        };
        // No initialization needed
    }
    /**
     * Generate a hash for a file.
     *
     * @param filePath Path to the file
     * @param algorithm Hash algorithm to use
     * @param chunkSize Size of chunks to read from file
     * @returns Hexadecimal hash string
     */
    async hashFile(filePath, algorithm = "sha256", chunkSize = 8192) {
        try {
            await fsStatPromise(filePath);
        }
        catch (e) {
            throw new Error(`File not found: ${filePath}`);
        }
        if (!this.SUPPORTED_ALGORITHMS[algorithm.toLowerCase()]) {
            throw new Error(`Unsupported algorithm: ${algorithm}. Supported algorithms: ${Object.keys(this.SUPPORTED_ALGORITHMS).join(", ")}`);
        }
        return new Promise((resolve, reject) => {
            const hash = this.SUPPORTED_ALGORITHMS[algorithm.toLowerCase()]();
            const stream = fs.createReadStream(filePath, { highWaterMark: chunkSize });
            stream.on("data", (chunk) => {
                hash.update(chunk);
            });
            stream.on("end", () => {
                resolve(hash.digest("hex"));
            });
            stream.on("error", (err) => {
                reject(err);
            });
        });
    }
    /**
     * Verify a file against an expected hash.
     *
     * @param filePath Path to the file
     * @param expectedHash Expected hash value
     * @param algorithm Hash algorithm to use
     * @returns True if the hash matches, False otherwise
     */
    async verifyFile(filePath, expectedHash, algorithm = "sha256") {
        const actualHash = await this.hashFile(filePath, algorithm);
        return actualHash.toLowerCase() === expectedHash.toLowerCase();
    }
    /**
     * Generate a hash for a string.
     *
     * @param inputString String to hash
     * @param algorithm Hash algorithm to use
     * @returns Hexadecimal hash string
     */
    hashString(inputString, algorithm = "sha256") {
        if (!this.SUPPORTED_ALGORITHMS[algorithm.toLowerCase()]) {
            throw new Error(`Unsupported algorithm: ${algorithm}. Supported algorithms: ${Object.keys(this.SUPPORTED_ALGORITHMS).join(", ")}`);
        }
        const hash = this.SUPPORTED_ALGORITHMS[algorithm.toLowerCase()]();
        hash.update(inputString);
        return hash.digest("hex");
    }
}
exports.Hashing = Hashing;
