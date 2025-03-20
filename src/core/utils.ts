/**
 * Utility functions for JnxBetaSec.
 */

import * as fs from "fs"
import * as path from "path"
import { promisify } from "util"
import { glob } from "glob"
import { Encryption } from "./encryption"
import { Hashing } from "./hashing"
import type { BatchProcessorOptions, HashAlgorithm, ContentType } from "../types"

const fsStatPromise = promisify(fs.stat)

export class BatchProcessor {
  private encryption: Encryption
  private hashing: Hashing

  constructor(options: BatchProcessorOptions = {}) {
    this.encryption = new Encryption({
      userId: options.userId || "default_user",
      organizationId: options.organizationId || "default",
    })
    this.hashing = new Hashing()
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
  public async encryptDirectory(
    directory: string,
    password: string,
    recursive = false,
    contentType?: ContentType,
  ): Promise<string[]> {
    try {
      // Check if directory exists
      const stats = await fsStatPromise(directory)
      if (!stats.isDirectory()) {
        throw new Error(`Not a directory: ${directory}`)
      }
    } catch (e) {
      throw new Error(`Invalid directory: ${directory}`)
    }

    // Find all files
    const pattern = recursive ? `${directory}/**/*` : `${directory}/*`
    const files = await glob(pattern, { nodir: true })

    // Filter out already encrypted files
    const filesToEncrypt = files.filter((file) => !file.toLowerCase().endsWith(".jnx"))

    const encryptedFiles: string[] = []

    // Process files
    for (const file of filesToEncrypt) {
      try {
        const encryptedFile = await this.encryption.encryptFile(file, password, contentType)
        encryptedFiles.push(encryptedFile)
      } catch (e) {
        console.error(`Failed to encrypt ${file}:`, e)
      }
    }

    return encryptedFiles
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
  public async decryptDirectory(
    directory: string,
    password: string,
    recursive = false,
    outputDir?: string,
  ): Promise<string[]> {
    try {
      // Check if directory exists
      const stats = await fsStatPromise(directory)
      if (!stats.isDirectory()) {
        throw new Error(`Not a directory: ${directory}`)
      }
    } catch (e) {
      throw new Error(`Invalid directory: ${directory}`)
    }

    // Create output directory if specified
    if (outputDir) {
      fs.mkdirSync(outputDir, { recursive: true })
    }

    // Find all .jnx files
    const pattern = recursive ? `${directory}/**/*.jnx` : `${directory}/*.jnx`
    const files = await glob(pattern, { nodir: true })

    const decryptedFiles: string[] = []

    // Process files
    for (const file of files) {
      try {
        let outputPath: string | undefined

        if (outputDir) {
          const relativePath = path.relative(directory, file)
          const baseFilename = path.basename(relativePath, ".jnx")
          outputPath = path.join(outputDir, baseFilename)
        }

        const decryptedFile = await this.encryption.decryptFile(file, password, outputPath)
        decryptedFiles.push(decryptedFile)
      } catch (e) {
        console.error(`Failed to decrypt ${file}:`, e)
      }
    }

    return decryptedFiles
  }

  /**
   * Generate hashes for all files in a directory.
   *
   * @param directory Directory containing files to hash
   * @param algorithm Hash algorithm to use
   * @param recursive Whether to process subdirectories
   * @returns Dictionary mapping file paths to their hashes
   */
  public async hashDirectory(
    directory: string,
    algorithm: HashAlgorithm = "sha256",
    recursive = false,
  ): Promise<Record<string, string>> {
    try {
      // Check if directory exists
      const stats = await fsStatPromise(directory)
      if (!stats.isDirectory()) {
        throw new Error(`Not a directory: ${directory}`)
      }
    } catch (e) {
      throw new Error(`Invalid directory: ${directory}`)
    }

    // Find all files
    const pattern = recursive ? `${directory}/**/*` : `${directory}/*`
    const files = await glob(pattern, { nodir: true })

    const fileHashes: Record<string, string> = {}

    // Process files
    for (const file of files) {
      try {
        const fileHash = await this.hashing.hashFile(file, algorithm)
        fileHashes[file] = fileHash
      } catch (e) {
        console.error(`Failed to hash ${file}:`, e)
      }
    }

    return fileHashes
  }
}

