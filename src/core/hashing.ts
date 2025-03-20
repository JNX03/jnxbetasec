/**
 * Hashing module for JnxBetaSec.
 */

import * as fs from "fs"
import * as crypto from "crypto"
import { promisify } from "util"
import type { HashAlgorithm } from "../types"

const fsReadFilePromise = promisify(fs.readFile)
const fsStatPromise = promisify(fs.stat)

export class Hashing {
  private readonly SUPPORTED_ALGORITHMS: Record<string, () => crypto.Hash> = {
    md5: () => crypto.createHash("md5"),
    sha1: () => crypto.createHash("sha1"),
    sha256: () => crypto.createHash("sha256"),
    sha384: () => crypto.createHash("sha384"),
    sha512: () => crypto.createHash("sha512"),
    blake2b512: () => crypto.createHash("blake2b512"),
    blake2s256: () => crypto.createHash("blake2s256"),
  };
  
  constructor() {
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
  public async hashFile(filePath: string, algorithm: HashAlgorithm = "sha256", chunkSize = 8192): Promise<string> {
    try {
      await fsStatPromise(filePath)
    } catch (e) {
      throw new Error(`File not found: ${filePath}`)
    }

    if (!this.SUPPORTED_ALGORITHMS[algorithm.toLowerCase()]) {
      throw new Error(
        `Unsupported algorithm: ${algorithm}. Supported algorithms: ${Object.keys(this.SUPPORTED_ALGORITHMS).join(", ")}`,
      )
    }

    return new Promise<string>((resolve, reject) => {
      const hash = this.SUPPORTED_ALGORITHMS[algorithm.toLowerCase()]()
      const stream = fs.createReadStream(filePath, { highWaterMark: chunkSize })

      stream.on("data", (chunk) => {
        hash.update(chunk)
      })

      stream.on("end", () => {
        resolve(hash.digest("hex"))
      })

      stream.on("error", (err) => {
        reject(err)
      })
    })
  }

  /**
   * Verify a file against an expected hash.
   *
   * @param filePath Path to the file
   * @param expectedHash Expected hash value
   * @param algorithm Hash algorithm to use
   * @returns True if the hash matches, False otherwise
   */
  public async verifyFile(
    filePath: string,
    expectedHash: string,
    algorithm: HashAlgorithm = "sha256",
  ): Promise<boolean> {
    const actualHash = await this.hashFile(filePath, algorithm)
    return actualHash.toLowerCase() === expectedHash.toLowerCase()
  }

  /**
   * Generate a hash for a string.
   *
   * @param inputString String to hash
   * @param algorithm Hash algorithm to use
   * @returns Hexadecimal hash string
   */
  public hashString(inputString: string, algorithm: HashAlgorithm = "sha256"): string {
    if (!this.SUPPORTED_ALGORITHMS[algorithm.toLowerCase()]) {
      throw new Error(
        `Unsupported algorithm: ${algorithm}. Supported algorithms: ${Object.keys(this.SUPPORTED_ALGORITHMS).join(", ")}`,
      )
    }

    const hash = this.SUPPORTED_ALGORITHMS[algorithm.toLowerCase()]()
    hash.update(inputString)
    return hash.digest("hex")
  }
}

