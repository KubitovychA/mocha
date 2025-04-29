import argon2 from 'argon2';
import fs from 'fs';
import { promisify } from 'util';

const FILE_PATH = 'password_hash.txt';

// Асинхронне збереження файлу
const writeFileAsync = promisify(fs.writeFile);
const chmodAsync = promisify(fs.chmod);
const readFileAsync = promisify(fs.readFile);

export function createPasswordManager({ hasher = argon2, fileSystem = fs } = {}) {
    return {
        // Зберігає хеш пароля в файл
        async savePassword(password) {
            try {
                const hash = await hasher.hash(password);
                await writeFileAsync(FILE_PATH, hash);
                await chmodAsync(FILE_PATH, 0o444); // Тільки для читання
                console.log('Пароль успішно збережено!');
            } catch (error) {
                console.error('Помилка при збереженні пароля:', error);
                throw new Error('Не вдалося зберегти пароль');
            }
        },

        // Перевіряє наявність файлу з хешем
        hashFileExists() {
            return fileSystem.existsSync(FILE_PATH);
        },

        // Читає хеш пароля з файлу
        async readHashFromFile() {
            try {
                await chmodAsync(FILE_PATH, 0o444); // Переконуємось, що файл доступний тільки для читання
                const hash = await readFileAsync(FILE_PATH, 'utf8');
                return hash.trim();
            } catch (err) {
                console.error('Помилка при читанні файлу:', err);
                throw new Error('Помилка читання файлу');
            }
        },

        // Перевіряє правильність пароля
        async verifyPassword(storedHash, inputPassword) {
            try {
                const isValid = await hasher.verify(storedHash, inputPassword);
                if (!isValid) {
                    throw new Error('Невірний пароль');
                }
                return true;
            } catch (error) {
                console.error('Помилка перевірки пароля:', error);
                throw new Error('Файл містить недійсний хеш або невірний пароль');
            }
        }
    };
}
