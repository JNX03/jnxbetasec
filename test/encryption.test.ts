/**
 * Tests for the encryption module.
 */

import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { Encryption } from "../src/core/encryption"
import { describe, beforeAll, afterAll, test, expect } from "@jest/globals"

describe("Encryption", () => {
  let tempDir: string
  let testFile: string
  let encryption: Encryption

  beforeAll(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "jnxbetasec-test-"))

    testFile = path.join(tempDir, "test-file.txt")
    fs.writeFileSync(testFile, "This is a test file for encryption.")

    const keyDir = path.join(tempDir, "keys")
    fs.mkdirSync(keyDir, { recursive: true })

    encryption = new Encryption({
      userId: "test-user",
      keyDir,
    })
  })

  afterAll(() => {
    fs.rmSync(tempDir, { recursive: true, force: true })
  })

  test("encrypt and decrypt cycle", async () => {
    const encryptedFile = await encryption.encryptFile(testFile, "test-password")
    expect(fs.existsSync(encryptedFile)).toBe(true)
    expect(path.extname(encryptedFile)).toBe(".jnx")
    const decryptedFile = await encryption.decryptFile(encryptedFile, "test-password")
    expect(fs.existsSync(decryptedFile)).toBe(true)
    const originalContent = fs.readFileSync(testFile, "utf8")
    const decryptedContent = fs.readFileSync(decryptedFile, "utf8")
    expect(decryptedContent).toBe(originalContent)
  })

  test("wrong password", async () => {
    const encryptedFile = await encryption.encryptFile(testFile, "test-password")
    await expect(encryption.decryptFile(encryptedFile, "wrong-password")).rejects.toThrow("Invalid password")
  })

  test("file not found", async () => {
    await expect(encryption.encryptFile("nonexistent-file.txt", "test-password")).rejects.toThrow("File not found")
  })
})

