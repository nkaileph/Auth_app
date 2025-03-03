const { createHmac } = require('crypto');
const { hash, compare } = require('bcryptjs');

exports.doHash = async (value, saltValue) => {
    try {
        const result = await hash(value, saltValue);
        return result;
    } catch (error) {
        throw new Error('Hashing failed');
    }
};

exports.doHashValidation = async (value, hashedValue) => {
    try {
        const result = await compare(value, hashedValue);
        return result;
    } catch (error) {
        throw new Error('Hash validation failed');
    }
};

exports.hmacProcess = (value,key) => {
    const result = createHmac('sha256', key)
    .update(value)
    .digest('hex');
    return result;
}
