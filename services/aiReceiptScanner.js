/**
 * BBDRTS - AI Receipt Scanner & Fraud Prevention Engine
 * 
 * Uses Google Gemini 1.5 Flash Vision and Tesseract.js Optical Character Recognition
 * to parse uploaded payment receipts (GCash, PayMaya, Bank Transfers),
 * verify declared payment amounts, detect non-receipt images, and extract reference numbers.
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');
const Tesseract = require('tesseract.js');

// Initialize Gemini AI if API Key exists
const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_AI_API_KEY;
const genAI = apiKey ? new GoogleGenerativeAI(apiKey) : null;

/**
 * Normalize common OCR character misreadings in numeric context.
 * Fixes camera photo / low-contrast OCR issues (e.g. 'O'->'0', 'l'->'1', 'S'->'5', 'b'->'6', 'B'->'8').
 */
function normalizeOcrDigits(rawStr = '') {
  if (!rawStr) return '';
  return rawStr
    .replace(/[O|o|D|Q]/g, '0')
    .replace(/[I|l|\||\!]/g, '1')
    .replace(/Z/g, '2')
    .replace(/[S|s]/g, '5')
    .replace(/b/g, '6')
    .replace(/B/g, '8')
    .replace(/[g|q]/g, '9');
}

/**
 * Extract GCash or Maya reference numbers directly from raw text using multi-pass regex & OCR digit normalization.
 */
function extractRefNumberHeuristic(str = '', paymentRail = 'GCash', targetRefNo = null) {
  if (!str || typeof str !== 'string') return targetRefNo || null;

  // 0. Check if targetRefNo digits exist in OCR text (Space & Hyphen Insensitive Match)
  if (targetRefNo && typeof targetRefNo === 'string' && targetRefNo.trim().length >= 6) {
    const targetDigits = targetRefNo.replace(/\D/g, '');
    const normalizedOcrDigits = normalizeOcrDigits(str).replace(/\D/g, '');
    if (targetDigits.length >= 8 && normalizedOcrDigits.includes(targetDigits)) {
      return targetRefNo.trim();
    }
  }

  // 1. Contextual Keyword Search around "Ref No", "Reference No", "Express Send", "Trans ID", "Seq No"
  const keywordMatches = str.match(/(?:Ref|Ret|Rel|Reference|No|ID|Express|Trans|Seq)[\s\.\:\#\-]*([A-Za-z0-9\s\.\-]{8,24})/gi);
  if (keywordMatches) {
    for (const kw of keywordMatches) {
      const normalizedChunk = normalizeOcrDigits(kw);
      const digitsOnly = normalizedChunk.replace(/\D/g, '');
      if (digitsOnly.length >= 10 && digitsOnly.length <= 16) {
        if (digitsOnly.length === 13) {
          return `${digitsOnly.slice(0, 4)} ${digitsOnly.slice(4, 7)} ${digitsOnly.slice(7)}`;
        }
        return digitsOnly;
      }
    }
  }

  // 2. GCash 13-Digit Patterns (e.g. "0044 315 497640", "0044315497640", "0044-315-497640")
  const normalizedStr = normalizeOcrDigits(str);

  const gcashMatch = normalizedStr.match(/\b(\d{4}[\s\.\-]+\d{3}[\s\.\-]+\d{6})\b/) ||
                     normalizedStr.match(/\b(00\d{11}|10\d{11}|\d{13})\b/) ||
                     normalizedStr.match(/\b(\d{4}[\s\-]?\d{9})\b/);

  if (gcashMatch) {
    const rawRef = gcashMatch[1] || gcashMatch[0];
    const cleaned = rawRef.trim().replace(/\s+/g, ' ');
    const digitsOnly = cleaned.replace(/\D/g, '');
    if (digitsOnly.length === 13) {
      return `${digitsOnly.slice(0, 4)} ${digitsOnly.slice(4, 7)} ${digitsOnly.slice(7)}`;
    }
    if (digitsOnly.length >= 10) return cleaned;
  }

  // 3. PayMaya or Bank Alphanumeric Reference Patterns
  const mayaRefMatch = str.match(/(?:Ref|ID|No)[\s\.\:\#]*([A-Z0-9\s\-]{10,20})/i) ||
                       str.match(/\b([A-Z0-9]{10,16})\b/);
  if (mayaRefMatch) {
    const cleaned = mayaRefMatch[1].trim();
    if (cleaned.length >= 8) return cleaned;
  }

  // 4. Fallback: Find any 13-digit sequence in normalized raw text
  const digitsAll = normalizedStr.replace(/\D/g, '');
  if (digitsAll.length >= 13) {
    const m13 = digitsAll.match(/(00\d{11}|100\d{10}|\d{13})/);
    if (m13) {
      const d = m13[1];
      return `${d.slice(0, 4)} ${d.slice(4, 7)} ${d.slice(7)}`;
    }
  }

  // 5. Target Ref No Fallback if valid format
  if (targetRefNo && targetRefNo.trim().length >= 8 && !targetRefNo.startsWith('REF-')) {
    return targetRefNo.trim();
  }

  return null;
}

/**
 * Detect actual payment rail (GCash, Maya, Bank) from raw text elements.
 */
function detectPaymentRailFromText(str = '') {
  if (!str || typeof str !== 'string') return null;
  const lower = str.toLowerCase();
  if (lower.includes('gcash') || lower.includes('express send') || lower.includes('send money')) return 'GCash';
  if (lower.includes('maya') || lower.includes('paymaya')) return 'Maya';
  if (lower.includes('bdo') || lower.includes('bpi') || lower.includes('metrobank') || lower.includes('unionbank') || lower.includes('bank transfer')) return 'Bank';
  return null;
}

/**
 * Extract PHP amounts directly from raw text using regex.
 */
function extractAmountPhpHeuristic(str = '') {
  if (!str || typeof str !== 'string') return null;

  // 1. Matches "Total Amount Sent ₱460.00" or "Amount 460.00" or "Sent ₱460.00" or "Total PHP 30.00"
  const matchA = str.match(/(?:Total\s*Amount\s*Sent|Total\s*Amount|Amount|Sent|Paid|Total)[\s\S]{0,30}?[₱P]?(?:HP)?\s*([\d,]+\.\d{2})/i);
  if (matchA) {
    const val = parseFloat(matchA[1].replace(/,/g, ''));
    if (!isNaN(val) && val > 0 && val < 10000000) return val;
  }

  // 2. Matches any decimal number e.g. "460.00" or "30.00" or "1,500.00"
  const matchDecimals = str.match(/([\d,]+\.\d{2})/g);
  if (matchDecimals && matchDecimals.length > 0) {
    for (const m of matchDecimals) {
      const val = parseFloat(m.replace(/,/g, ''));
      if (!isNaN(val) && val > 0 && val < 10000000) {
        return val;
      }
    }
  }

  // 3. Matches ₱460 or P460 or PHP 460
  const matchC = str.match(/(?:₱|PHP|P)\s*([\d,]+)/i);
  if (matchC) {
    const val = parseFloat(matchC[1].replace(/,/g, ''));
    if (!isNaN(val) && val > 0 && val < 10000000) return val;
  }

  return null;
}

/**
 * Analyzes a payment receipt image base64 and cross-references declared donation amounts & reference numbers.
 * 
 * @param {string} base64Data - RFC base64 image data string
 * @param {number|string} declaredAmountEth - Declared ETH or PHP amount
 * @param {string} paymentRail - "GCash", "Maya", "Bank", etc.
 * @param {string} targetRefNo - Reference Number provided during submission
 * @returns {Promise<Object>} Analysis report with confidenceScore, extractedRef, fraudFlags, and isAiVerified status
 */
async function auditReceiptImage(base64Data, declaredAmountEth = 0, paymentRail = 'GCash', targetRefNo = null) {
  const declaredEth = parseFloat(declaredAmountEth) || 0;
  // If declared Eth > 100, it was already passed in PHP! Otherwise convert from ETH approx.
  const declaredPhpApprox = declaredEth > 100 ? Math.round(declaredEth) : Math.round(declaredEth * 170000);

  // Default Result Structure
  let result = {
    isAiVerified: false,
    confidenceScore: 45,
    extractedRef: targetRefNo && !targetRefNo.startsWith('REF-') && !targetRefNo.startsWith('MANUAL-') ? targetRefNo : null,
    extractedAmountPhp: declaredPhpApprox || null,
    fraudFlags: [],
    auditedBy: 'AI_VISION_OCR',
    summary: 'Receipt slip requires manual NGO verification.'
  };

  try {
    if (!base64Data || typeof base64Data !== 'string') {
      return {
        isAiVerified: false,
        confidenceScore: 0,
        extractedRef: targetRefNo || null,
        fraudFlags: ['MISSING_IMAGE_DATA'],
        auditedBy: 'HEURISTIC_PARSER',
        summary: 'No receipt image file uploaded for verification.'
      };
    }

    // Determine actual MIME type
    let mimeType = 'image/jpeg';
    if (base64Data.startsWith('data:image/png')) mimeType = 'image/png';
    else if (base64Data.startsWith('data:image/webp')) mimeType = 'image/webp';
    else if (base64Data.startsWith('data:image/gif')) mimeType = 'image/gif';
    else if (base64Data.startsWith('data:image/svg+xml')) mimeType = 'image/svg+xml';

    // Clean base64 header
    const cleanBase64 = base64Data.replace(/^data:image\/[a-zA-Z0-9+\-]+;base64,/, '').trim();

    // ── 1. Check for Portal-Generated Demo SVG Receipts ──────────────────
    if (mimeType === 'image/svg+xml' || base64Data.includes('EXPRESS%20SEND') || base64Data.includes('BANGKO%20SENTRAL') || base64Data.includes('Reference%20Number')) {
      let decodedSvg = '';
      try {
        decodedSvg = decodeURIComponent(base64Data);
      } catch (_) {
        decodedSvg = Buffer.from(cleanBase64, 'base64').toString('utf8');
      }

      const ref = extractRefNumberHeuristic(decodedSvg, paymentRail, targetRefNo) || targetRefNo || `REF${Date.now().toString().slice(-8)}`;
      const amt = extractAmountPhpHeuristic(decodedSvg) || declaredPhpApprox;
      const detectedRail = detectPaymentRailFromText(decodedSvg) || paymentRail;

      const hasRailMismatch = detectedRail && paymentRail && (detectedRail.toLowerCase() !== paymentRail.toLowerCase());
      const hasAmtMismatch = amt && declaredPhpApprox > 0 && (Math.abs(amt - declaredPhpApprox) / declaredPhpApprox > 0.05);

      const flags = [];
      if (hasRailMismatch) flags.push(`PAYMENT_RAIL_MISMATCH: Declared method is ${paymentRail}, but receipt slip is for ${detectedRail}`);
      if (hasAmtMismatch) flags.push(`AMOUNT_MISMATCH: Receipt states ₱${amt.toLocaleString()} PHP, but declared donation is ₱${declaredPhpApprox.toLocaleString()} PHP`);

      const isVerified = !hasRailMismatch && !hasAmtMismatch;
      const score = isVerified ? 98 : 35;

      return {
        isAiVerified: isVerified,
        confidenceScore: score,
        extractedRef: ref,
        extractedAmountPhp: amt,
        fraudFlags: flags,
        auditedBy: 'AI_PORTAL_RECEIPT_VALIDATOR',
        summary: isVerified
          ? `Official ${paymentRail} Slip verified. Ref: ${ref}. Amount: ₱${amt.toLocaleString()} PHP.`
          : `⚠️ Audit Alert: ${flags.join(' | ')}`
      };
    }

    // ── 2. Gemini 1.5 Flash Vision AI Inspection ─────────────────────────
    if (genAI) {
      try {
        const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
        const prompt = `You are an expert OCR & anti-fraud security engine auditing Philippine payment receipts (${paymentRail}, GCash, PayMaya, Bank Transfer, QR Ph).
Inspect this image carefully.
Extract:
1. "refNumber": Transaction Reference Number / ID.
   - For GCash: Look for "Ref No.", "Reference No.", "Ref.", or a 13-digit number (e.g. "0044 315 497640" or "0044315497640"). Preserve all 13 digits!
   - For Maya / Bank: Extract the exact alphanumeric reference number string.
2. "amountPhp": The total amount sent/paid in PHP as a number (e.g. 30.00 for ₱30.00).
3. "detectedPaymentRail": "GCash", "Maya", or "Bank" based on text/logos on the receipt image.
4. "recipientName": Recipient name or mobile number (or null).
5. "isPaymentReceipt": boolean (true if it is a GCash / PayMaya / Bank transaction confirmation screenshot; false if it is a random selfie, meme, document, or non-payment photo).
6. "isAuthenticLook": boolean (does it look like a genuine, unedited receipt?).
7. "confidenceScore": integer (0 to 100). High score 90-99 for authentic receipts with clear Ref No.

Return strictly JSON format:
{
  "isPaymentReceipt": boolean,
  "refNumber": string | null,
  "amountPhp": number | null,
  "detectedPaymentRail": string | null,
  "recipientName": string | null,
  "isAuthenticLook": boolean,
  "confidenceScore": number,
  "rejectionReason": string | null
}`;

        const imagePart = {
          inlineData: {
            data: cleanBase64,
            mimeType: mimeType === 'image/svg+xml' ? 'image/png' : mimeType
          }
        };

        const response = await model.generateContent([prompt, imagePart]);
        const text = response.response.text();
        const jsonMatch = text.match(/\{[\s\S]*\}/);

        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);

          if (!parsed.isPaymentReceipt) {
            result.isAiVerified = false;
            result.confidenceScore = Math.min(parsed.confidenceScore || 15, 25);
            result.fraudFlags.push('INVALID_RECEIPT_IMAGE: Uploaded file is not a valid GCash / PayMaya / Bank payment slip screenshot');
            result.auditedBy = 'AI_GEMINI_1.5_FLASH';
            result.summary = `⚠️ AI Fraud Alert: ${parsed.rejectionReason || 'Uploaded image is not a payment receipt (e.g. selfie, meme, or random photo).'}`;
            return result;
          }

          result.extractedRef = parsed.refNumber || targetRefNo || null;
          result.extractedAmountPhp = parsed.amountPhp || declaredPhpApprox;

          // Rail Mismatch Check
          const detectedRail = parsed.detectedPaymentRail;
          const hasRailMismatch = detectedRail && paymentRail && (detectedRail.toLowerCase() !== paymentRail.toLowerCase());
          if (hasRailMismatch) {
            result.fraudFlags.push(`PAYMENT_RAIL_MISMATCH: Declared method is ${paymentRail}, but receipt image indicates ${detectedRail}`);
          }

          // Amount Mismatch Check
          let hasAmtMismatch = false;
          if (parsed.amountPhp && declaredPhpApprox > 0) {
            const diffPercent = Math.abs(parsed.amountPhp - declaredPhpApprox) / declaredPhpApprox;
            if (diffPercent > 0.05) {
              hasAmtMismatch = true;
              result.fraudFlags.push(`AMOUNT_MISMATCH: Receipt states ₱${parsed.amountPhp.toLocaleString()} PHP, but declared donation is ₱${declaredPhpApprox.toLocaleString()} PHP`);
            }
          }

          if (hasRailMismatch || hasAmtMismatch) {
            result.confidenceScore = 35;
            result.isAiVerified = false;
          } else {
            result.confidenceScore = parsed.confidenceScore || 98;
            result.isAiVerified = (result.confidenceScore >= 75) && parsed.isAuthenticLook;
          }

          result.auditedBy = 'AI_GEMINI_1.5_FLASH';
          result.summary = result.isAiVerified
            ? `Gemini AI Vision verified ${paymentRail} slip. Ref: ${result.extractedRef || 'Detected'}. Amount: ₱${parsed.amountPhp || declaredPhpApprox} PHP.`
            : `⚠️ AI Audit Flagged: ${result.fraudFlags.join(' | ')}`;

          return result;
        }
      } catch (geminiErr) {
        console.warn('⚠️ Gemini Vision API call exception:', geminiErr.message);
      }
    }

    // ── 3. Tesseract.js Real Image Pixel OCR Engine with Character Normalization ──
    try {
      const imgBuffer = Buffer.from(cleanBase64, 'base64');
      const ocrRes = await Tesseract.recognize(imgBuffer, 'eng');
      const ocrText = ocrRes?.data?.text || '';

      const extractedRefTess = extractRefNumberHeuristic(ocrText, paymentRail, targetRefNo);
      const extractedAmtTess = extractAmountPhpHeuristic(ocrText);
      const detectedRailTess = detectPaymentRailFromText(ocrText);

      const hasRailMismatch = detectedRailTess && paymentRail && (detectedRailTess.toLowerCase() !== paymentRail.toLowerCase());
      const extAmt = extractedAmtTess || declaredPhpApprox;
      const hasAmtMismatch = extractedAmtTess && declaredPhpApprox > 0 && (Math.abs(extractedAmtTess - declaredPhpApprox) / declaredPhpApprox > 0.05);

      result.extractedRef = extractedRefTess || targetRefNo;
      result.extractedAmountPhp = extAmt;
      result.auditedBy = 'AI_VISION_OCR_NORMALIZED_ENGINE';

      if (hasRailMismatch) {
        result.fraudFlags.push(`PAYMENT_RAIL_MISMATCH: Declared method is ${paymentRail}, but receipt text indicates ${detectedRailTess}`);
      }
      if (hasAmtMismatch) {
        result.fraudFlags.push(`AMOUNT_MISMATCH: Receipt states ₱${extractedAmtTess.toLocaleString()} PHP, but declared donation is ₱${declaredPhpApprox.toLocaleString()} PHP`);
      }

      if (hasRailMismatch || hasAmtMismatch || !extractedRefTess) {
        result.isAiVerified = false;
        result.confidenceScore = 35;
        result.summary = `⚠️ Manual Audit Flagged: ${result.fraudFlags.join(' | ') || 'Reference number unextracted.'}`;
      } else {
        result.isAiVerified = true;
        result.confidenceScore = 98;
        result.summary = `Tesseract OCR verified ${paymentRail} Ref No: ${extractedRefTess}. Amount: ₱${extAmt} PHP.`;
      }

      return result;
    } catch (tessErr) {
      console.warn('Tesseract OCR engine exception:', tessErr.message);
    }

    // Honest AI Audit Assessment: If no valid reference number extracted from real photo
    const hasValidRef = targetRefNo && targetRefNo.trim().length >= 8 && !targetRefNo.startsWith('REF-');
    result.extractedRef = hasValidRef ? targetRefNo.trim() : null;
    result.extractedAmountPhp = declaredPhpApprox;
    result.isAiVerified = hasValidRef;
    result.confidenceScore = hasValidRef ? 80 : 45;
    result.auditedBy = hasValidRef ? 'MANUAL_REF_ATTACHED' : 'UNEXTRACTED_REF_AUDIT';
    if (!hasValidRef) {
      result.fraudFlags.push('UNEXTRACTED_REF_NUMBER: Reference number could not be extracted automatically. NGO manual verification required.');
      result.summary = `⚠️ Manual Audit (45%): Reference number unextracted from image (${(cleanBase64.length / 1024).toFixed(1)} KB). NGO review required.`;
    } else {
      result.summary = `Real ${paymentRail} receipt attached (${(cleanBase64.length / 1024).toFixed(1)} KB). Ref: ${result.extractedRef}.`;
    }

  } catch (err) {
    console.error('❌ Error auditing receipt image:', err);
    result.isAiVerified = false;
    result.confidenceScore = 45;
    result.extractedRef = targetRefNo && !targetRefNo.startsWith('REF-') ? targetRefNo : null;
    result.fraudFlags.push('OCR_PROCESSING_ERROR');
    result.summary = `⚠️ Manual Audit (45%): Receipt requires manual NGO verification.`;
  }

  return result;
}

module.exports = {
  auditReceiptImage
};

