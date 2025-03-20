/**
 * Type definitions for JnxBetaSec
 */
export interface EncryptionOptions {
    userId: string;
    organizationId?: string;
    keyDir?: string;
}
export interface FileMetadata {
    filename: string;
    originalExtension: string;
    contentType: string;
    fileSize: number;
    createdDate: string;
    modifiedDate: string;
    encryptedDate: string;
    encryptionVersion: string;
    sha512Hash: string;
    userId: string;
    organizationId: string;
    imageWidth?: number;
    imageHeight?: number;
    imageFormat?: string;
    imageMode?: string;
}
export interface KeysBundle {
    aesKey: string;
    aesIv: string;
    chachaKey: string;
    chachaNonce: string;
    salt: string;
}
export interface BatchProcessorOptions {
    userId?: string;
    organizationId?: string;
}
export type HashAlgorithm = "md5" | "sha1" | "sha256" | "sha384" | "sha512";
export type ContentType = "image" | "text";
