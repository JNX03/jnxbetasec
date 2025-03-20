/**
 * Tests for the hashing module.
 */

import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { Hashing } from "../src/core/hashing"
import { describe, beforeAll, afterAll, test, expect } from "@jest/globals"

describe("Hashing", () => {
  let tempDir: string
  let testFile: string
  let hashing: Hashing

  beforeAll(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "jnxbetasec-test-"))

    testFile = path.join(tempDir, "test-file.txt")
    fs.writeFileSync(testFile, "This is a test file for hashing.")

    hashing = new Hashing()
  })

  afterAll(() => {
    fs.rmSync(tempDir, { recursive: true, force: true })
  })

  test("hash file with different algorithms", async () => {
    for (const algorithm of ["md5", "sha1", "sha256", "sha512"] as const) {
      const hash = await hashing.hashFile(testFile, algorithm)
      expect(typeof hash).toBe("string")
      expect(hash.length).toBeGreaterThan(0)
    }
  })

  test("verify file", async () => {
    const hash = await hashing.hashFile(testFile, "sha256")

    const result = await hashing.verifyFile(testFile, hash, "sha256")
    expect(result).toBe(true)

    const wrongResult = await hashing.verifyFile(testFile, "wrong-hash", "sha256")
    expect(wrongResult).toBe(false)
  })

  test("hash string", () => {
    const testString = "This is a test string for hashing."

    for (const algorithm of ["md5", "sha1", "sha256", "sha512"] as const) {
      const hash = hashing.hashString(testString, algorithm)
      expect(typeof hash).toBe("string")
      expect(hash.length).toBeGreaterThan(0)
    }
  })

  test("unsupported algorithm", async () => {
    // @ts-ignore - Testing invalid input
    await expect(hashing.hashFile(testFile, "unsupported-algorithm")).rejects.toThrow("Unsupported algorithm")
  })
})

