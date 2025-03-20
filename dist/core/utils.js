"use strict";
/**
 * Utility functions for JnxBetaSec.
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
exports.BatchProcessor = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const util_1 = require("util");
const glob_1 = require("glob");
const encryption_1 = require("./encryption");
const hashing_1 = require("./hashing");
const fsStatPromise = (0, util_1.promisify)(fs.stat);
class BatchProcessor {
    constructor(options = {}) {
        this.encryption = new encryption_1.Encryption({
            userId: options.userId || "default_user",
            organizationId: options.organizationId || "default",
        });
        this.hashing = new hashing_1.Hashing();
    }
    /**
     * Encrypt all files in a directory.
     *
     * @param directory Directory containing files to encrypt
     * @param password Password for encryption
     * @param recursive Whether to process subdirectories
     * @param contentType Content type for all files (optional)
     * @returns List of paths to encrypted files
     */
    async encryptDirectory(directory, password, recursive = false, contentType) {
        try {
            // Check if directory exists
            const stats = await fsStatPromise(directory);
            if (!stats.isDirectory()) {
                throw new Error(`Not a directory: ${directory}`);
            }
        }
        catch (e) {
            throw new Error(`Invalid directory: ${directory}`);
        }
        // Find all files
        const pattern = recursive ? `${directory}/**/*` : `${directory}/*`;
        const files = await (0, glob_1.glob)(pattern, { nodir: true });
        // Filter out already encrypted files
        const filesToEncrypt = files.filter((file) => !file.toLowerCase().endsWith(".jnx"));
        const encryptedFiles = [];
        // Process files
        for (const file of filesToEncrypt) {
            try {
                const encryptedFile = await this.encryption.encryptFile(file, password, contentType);
                encryptedFiles.push(encryptedFile);
            }
            catch (e) {
                console.error(`Failed to encrypt ${file}:`, e);
            }
        }
        return encryptedFiles;
    }
    /**
     * Decrypt all .jnx files in a directory.
     *
     * @param directory Directory containing files to decrypt
     * @param password Password for decryption
     * @param recursive Whether to process subdirectories
     * @param outputDir Directory to save decrypted files (optional)
     * @returns List of paths to decrypted files
     */
    async decryptDirectory(directory, password, recursive = false, outputDir) {
        try {
            // Check if directory exists
            const stats = await fsStatPromise(directory);
            if (!stats.isDirectory()) {
                throw new Error(`Not a directory: ${directory}`);
            }
        }
        catch (e) {
            throw new Error(`Invalid directory: ${directory}`);
        }
        // Create output directory if specified
        if (outputDir) {
            fs.mkdirSync(outputDir, { recursive: true });
        }
        // Find all .jnx files
        const pattern = recursive ? `${directory}/**/*.jnx` : `${directory}/*.jnx`;
        const files = await (0, glob_1.glob)(pattern, { nodir: true });
        const decryptedFiles = [];
        // Process files
        for (const file of files) {
            try {
                let outputPath;
                if (outputDir) {
                    const relativePath = path.relative(directory, file);
                    const baseFilename = path.basename(relativePath, ".jnx");
                    outputPath = path.join(outputDir, baseFilename);
                }
                const decryptedFile = await this.encryption.decryptFile(file, password, outputPath);
                decryptedFiles.push(decryptedFile);
            }
            catch (e) {
                console.error(`Failed to decrypt ${file}:`, e);
            }
        }
        return decryptedFiles;
    }
    /**
     * Generate hashes for all files in a directory.
     *
     * @param directory Directory containing files to hash
     * @param algorithm Hash algorithm to use
     * @param recursive Whether to process subdirectories
     * @returns Dictionary mapping file paths to their hashes
     */
    async hashDirectory(directory, algorithm = "sha256", recursive = false) {
        try {
            // Check if directory exists
            const stats = await fsStatPromise(directory);
            if (!stats.isDirectory()) {
                throw new Error(`Not a directory: ${directory}`);
            }
        }
        catch (e) {
            throw new Error(`Invalid directory: ${directory}`);
        }
        // Find all files
        const pattern = recursive ? `${directory}/**/*` : `${directory}/*`;
        const files = await (0, glob_1.glob)(pattern, { nodir: true });
        const fileHashes = {};
        // Process files
        for (const file of files) {
            try {
                const fileHash = await this.hashing.hashFile(file, algorithm);
                fileHashes[file] = fileHash;
            }
            catch (e) {
                console.error(`Failed to hash ${file}:`, e);
            }
        }
        return fileHashes;
    }
}
exports.BatchProcessor = BatchProcessor;
