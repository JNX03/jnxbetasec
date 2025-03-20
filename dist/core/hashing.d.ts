/**
 * Hashing module for JnxBetaSec.
 */
import type { HashAlgorithm } from "../types";
export declare class Hashing {
    private readonly SUPPORTED_ALGORITHMS;
    constructor();
    /**
     * Generate a hash for a file.
     *
     * @param filePath Path to the file
     * @param algorithm Hash algorithm to use
     * @param chunkSize Size of chunks to read from file
     * @returns Hexadecimal hash string
     */
    hashFile(filePath: string, algorithm?: HashAlgorithm, chunkSize?: number): Promise<string>;
    /**
     * Verify a file against an expected hash.
     *
     * @param filePath Path to the file
     * @param expectedHash Expected hash value
     * @param algorithm Hash algorithm to use
     * @returns True if the hash matches, False otherwise
     */
    verifyFile(filePath: string, expectedHash: string, algorithm?: HashAlgorithm): Promise<boolean>;
    /**
     * Generate a hash for a string.
     *
     * @param inputString String to hash
     * @param algorithm Hash algorithm to use
     * @returns Hexadecimal hash string
     */
    hashString(inputString: string, algorithm?: HashAlgorithm): string;
}
