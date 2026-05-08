import init, {
  derive_master_key,
  derive_subkeys,
  encrypt,
  decrypt,
  random_bytes,
  sha256,
  hmac_sha256,
  generate_zkp_keypair,
  create_zkp_proof,
} from 'safehaven-crypto'

let initialized = false

export async function initCrypto(): Promise<void> {
  if (initialized) return
  await init()
  initialized = true
}

export {
  derive_master_key,
  derive_subkeys,
  encrypt,
  decrypt,
  random_bytes,
  sha256,
  hmac_sha256,
  generate_zkp_keypair,
  create_zkp_proof,
}

/** Convert Uint8Array to base64 string. */
export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  const len = bytes.byteLength
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]!)
  }
  return btoa(binary)
}

/** Convert base64 string to Uint8Array. */
export function fromBase64(str: string): Uint8Array {
  const binary = atob(str)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
