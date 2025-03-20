/**
 * Utility functions for JnxBetaSec.
 */
import type { BatchProcessorOptions, HashAlgorithm, ContentType } from "../types";
export declare class BatchProcessor {
    private encryption;
    private hashing;
    constructor(options?: BatchProcessorOptions);
    /**
     * Encrypt all files in a directory.
     *
     * @param directory Directory containing files to encrypt
     * @param password Password for encryption
     * @param recursive Whether to process subdirectories
     * @param contentType Content type for all files (optional)
     * @returns List of paths to encrypted files
     */
    encryptDirectory(directory: string, password: string, recursive?: boolean, contentType?: ContentType): Promise<string[]>;
    /**
     * Decrypt all .jnx files in a directory.
     *
     * @param directory Directory containing files to decrypt
     * @param password Password for decryption
     * @param recursive Whether to process subdirectories
     * @param outputDir Directory to save decrypted files (optional)
     * @returns List of paths to decrypted files
     */
    decryptDirectory(directory: string, password: string, recursive?: boolean, outputDir?: string): Promise<string[]>;
    /**
     * Generate hashes for all files in a directory.
     *
     * @param directory Directory containing files to hash
     * @param algorithm Hash algorithm to use
     * @param recursive Whether to process subdirectories
     * @returns Dictionary mapping file paths to their hashes
     */
    hashDirectory(directory: string, algorithm?: HashAlgorithm, recursive?: boolean): Promise<Record<string, string>>;
}
