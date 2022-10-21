import { createHash, createHmac } from "crypto"

export function sha256 (payload: string) {
    return createHash("sha256").update(payload).digest()
}

export function hmacSha256 (key: string | Uint8Array, msg: string) {
    return createHmac("sha256", key).update(msg).digest()
}

export function hmacSha256Hex (key: string | Uint8Array, msg: string) {
    return createHmac("sha256", key).update(msg).digest("hex")
}

export function sha256Async (payload: string) {
    return new Promise<Buffer>((resolve, reject) => {
        const hash = createHash("sha256")
        hash.on("readable", () => {
            const data = hash.read()
            if (data) resolve(data)
        })
        hash.on("error", (error: Error) => reject(error))
        hash.write(payload)
        hash.end()
    })
}

function hmacSha256AsyncBase (key: string | Uint8Array, msg: string, digest: null): Promise<Buffer>
function hmacSha256AsyncBase (key: string | Uint8Array, msg: string, digest: 'utf-8' | 'hex' | 'base64'): Promise<string>
function hmacSha256AsyncBase (key: string | Uint8Array, msg: string, digest: 'utf-8' | 'hex' | 'base64' | null): Promise<string | Buffer> {
    return new Promise((resolve, reject) => {
        const hash = createHmac("sha256", key)
        hash.on("readable", () => {
            const data = hash.read()
            if (data) {
                if (digest) {
                    return resolve(data.toString(digest))
                }
                return resolve(data)
            }
        })
        hash.on("error", (error: Error) => reject(error))
        hash.write(msg)
        hash.end()
    })
}

export function hmacSha256Async (key: string | Uint8Array, msg: string) {
    return hmacSha256AsyncBase(key, msg, null)
}

export function hmacSha256AsyncHex (key: string | Uint8Array, msg: string) {
    return hmacSha256AsyncBase(key, msg, 'hex')
}
