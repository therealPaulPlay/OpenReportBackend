const profanityList = require('../JSON/profanity-list.json');

let profanityRegex;

try {
    const escaped = profanityList.list.map(word =>
        word.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')
    );
    profanityRegex = new RegExp(`\\b(${escaped.join('|')})\\b`, 'gi');
} catch (error) {
    console.error('Error generating profanity regex:', error);
}

function filterProfanity(text) {
    if (!text || !profanityRegex) return text;
    try {
        return text.replace(profanityRegex, match => '*'.repeat(match.length)); // Censor bad words with star character
    } catch (error) {
        console.error('Error filtering profanity:', error);
        return text;
    }
}

module.exports = filterProfanity;