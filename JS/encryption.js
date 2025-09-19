import crypto from 'crypto';

const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const ALGORITHM = 'aes-256-gcm';

function encryptPassword(password) {
    const iv = crypto.randomBytes(12); // 96-bit IV for GCM (recommended size)
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    cipher.setAAD(Buffer.from('db_password')); // Additional authenticated data

    let encrypted = cipher.update(password, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    // Combine IV, auth tag, and encrypted data
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
}

function decryptPassword(encryptedPassword) {
    if (!encryptedPassword || typeof encryptedPassword !== 'string') return encryptedPassword;

    const parts = encryptedPassword.split(':');
    if (parts.length !== 3) return encryptedPassword; // Not encrypted, return as-is

    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];

    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    decipher.setAAD(Buffer.from('db_password'));

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

export {
    encryptPassword,
    decryptPassword
};