const xlsx = require('xlsx');
const fs = require('fs');
const path = require('path');

/**
 * Parse Excel/CSV file and return data as JSON
 * @param {string} filePath - Path to the uploaded file
 * @returns {Array} - Parsed data as array of objects
 */
const parseExcelFile = (filePath) => {
    try {
        // Read the file
        const workbook = xlsx.readFile(filePath);
        
        // Get the first sheet
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        
        // Convert to JSON
        const data = xlsx.utils.sheet_to_json(worksheet, {
            raw: false, // Parse dates and numbers properly
            defval: null // Default value for empty cells
        });
        
        return data;
    } catch (error) {
        throw new Error(`Failed to parse Excel file: ${error.message}`);
    }
};

/**
 * Delete uploaded file after processing
 * @param {string} filePath - Path to the file to delete
 */
const deleteFile = (filePath) => {
    try {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
    } catch (error) {
        console.error('Error deleting file:', error);
    }
};

/**
 * Validate required fields in parsed data
 * @param {Array} data - Parsed data array
 * @param {Array} requiredFields - Array of required field names
 * @returns {Object} - { isValid, missingFields, invalidRows }
 */
const validateRequiredFields = (data, requiredFields) => {
    const missingFields = new Set();
    const invalidRows = [];
    
    data.forEach((row, index) => {
        const rowNumber = index + 2; // +2 because of header row and 0-based index
        const rowMissingFields = [];
        
        requiredFields.forEach(field => {
            if (!row[field] || row[field].toString().trim() === '') {
                missingFields.add(field);
                rowMissingFields.push(field);
            }
        });
        
        if (rowMissingFields.length > 0) {
            invalidRows.push({
                row: rowNumber,
                missingFields: rowMissingFields,
                data: row
            });
        }
    });
    
    return {
        isValid: invalidRows.length === 0,
        missingFields: Array.from(missingFields),
        invalidRows
    };
};

module.exports = {
    parseExcelFile,
    deleteFile,
    validateRequiredFields
};
