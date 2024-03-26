const {createHash} = require('crypto')

export const WITNESS_RESERVED_VALUE = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
)

export const hash256 = (buffer) => {
  return createHash('sha256').update(
    createHash('sha256').update(buffer, 'hex').digest(),
  ).digest('hex')
}

export const generateMerkleRoot = (txids) => {
    if (txids.length === 0) return null

    // reverse the txids
    let level = txids.map((txid) => Buffer.from(txid, 'hex').reverse().toString('hex'))

    while (level.length > 1) {
        const nextLevel = []

        for( let i = 0; i < level.length; i += 2) {
            const left = Buffer.from(level[i], 'hex')
            const right = Buffer.from(level[i + 1] || level[i], 'hex')
            const combined = Buffer.concat([left, right])
            nextLevel.push(hash256(combined.toString('hex')))
        }

        level = nextLevel
    }

    return level[0]
}