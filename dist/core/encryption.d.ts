/**
 * Encryption module for JnxBetaSec.
 */
import type { EncryptionOptions, ContentType } from "../types";
export declare class Encryption {
    private readonly FILE_SIGNATURE;
    private readonly ITERATIONS;
    private readonly KEY_LENGTH;
    private userId;
    private organizationId;
    private keyDir;
    private privateKey;
    private publicKey;
    constructor(options: EncryptionOptions);
    private initializeKeys;
    exportKey(keyType: string, outputPath: string): Promise<void>;
    private deriveKeys;
    private generateFileMetadata;
    encryptFile(filePath: string, password: string, contentType?: ContentType): Promise<string>;
    decryptFile(filePath: string, password: string, outputPath?: string): Promise<string>;
}
