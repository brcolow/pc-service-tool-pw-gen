window.onload = async function() {
  tryDecodePassword("LOmi83NMMIb2//Yh9fXyDg");
  userID = "KOKOMO";
  const generatedPassword = await generatePassword(userID, 3, 5, 1, AccessLevel.Development, Brand.Hyster, UserType.Development);
  console.log("Your username is: " + userID + "\r\nYour generated password is:\r\n" + generatedPassword);
  tryDecodePassword(generatedPassword);
};

function convertBytesToBase36String(bytes) {
  const dataView = new DataView(bytes.buffer);
  let int64 = dataView.getBigInt64(0, true);
  let base36String = "";
  while (int64 > 0) {
    let index = int64 % 36n;
    int64 /= 36n;
    base36String += base36Map[index];
  }
  return base36String;
}

function convertBase36StringToBytes(base36String) {
  let decimalValue = 0n;
  let power = 0;

  for (let i = 0; i < base36String.length; i++) {
    const charCode = base36String.charCodeAt(i);
    const digitValue = charCode >= 48 && charCode <= 57 ? charCode - 48 : charCode - 55;
    decimalValue += BigInt(digitValue) * 36n ** BigInt(power);
    power++;
  }

  const buffer = new ArrayBuffer(8);
  const view = new BigUint64Array(buffer);
  view[0] = decimalValue;

  return new Uint8Array(buffer);
}

const base36Map = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

function getCurrentDatePlusYears(numYears) {
  const currentDate = new Date();
  currentDate.setFullYear(currentDate.getFullYear() + Number(numYears));
  return currentDate;
}

function ticksToDate(ticks) {
  const ticksPerMillisecond = 10000;
  const csUnixStartDateTicks = 621355968000000000;

  const jsTicks = (ticks - csUnixStartDateTicks) / ticksPerMillisecond;
  return new Date(jsTicks);
}

async function generatePassword(userID, years, majorVersion, minorVersion, accessLevel, brand, userType) {
  // Strip off minor version numbers passed the first digit for compatibility.
  minorVersion = parseInt(minorVersion.toString()[0], 10);
  let outputBuffer = new Uint8Array(16);
  let userIDBytes = convertBase36StringToBytes(userID);
  outputBuffer[0] = userIDBytes[0];
  outputBuffer[1] = userIDBytes[1];
  outputBuffer[2] = userIDBytes[2];
  outputBuffer[3] = userIDBytes[3];
  outputBuffer[4] = userIDBytes[4];
  outputBuffer[5] = userIDBytes[5];
  // Modify the 5th byte to set bits 4, 5, 6 for accessLevel
  outputBuffer[5] |= (accessLevel.value << 4) & 0xF0;
  // 621355968000000000 is the number of Ticks since Jan 1st, 1 A.D. to the Unix epoch (January 1, 1970, 00:00:00 UTC), where Javascript dates start
  const targetTimestamp = (getCurrentDatePlusYears(years).getTime()) * 10000 + 621355968000000000 - (getCurrentDatePlusYears(3).getTimezoneOffset() * 600000000);
  // Assign the timestamp bytes to the outputBuffer
  outputBuffer[9] = Number((BigInt(targetTimestamp) >> 56n) & 0xFFn);
  outputBuffer[8] = Number((BigInt(targetTimestamp) >> 48n) & 0xFFn);
  outputBuffer[7] = Number((BigInt(targetTimestamp) >> 40n) & 0xFFn);
  outputBuffer[6] = Number((BigInt(targetTimestamp) >> 32n) & 0xFFn);
  // Major version
  outputBuffer[10] = majorVersion;
  // Minor version
  outputBuffer[11] = minorVersion;
  // Combine the brand and userType values
  let brandValue = brand.value;
  let userTypeValue = userType.value << 4; // Shift left by 4 for userType
  let combinedValue = brandValue | userTypeValue;
  outputBuffer[12] = combinedValue;

  const key = new Uint8Array([22, 210, 29, 30, 134, 215, 228, 40, 196, 153, 254, 103, 184, 52, 88, 201]);
  const iv = new Uint8Array([128, 214, 58, 190, 150, 225, 47, 176, 184, 252, 245, 124, 237, 239, 20, 93]);
  const encryptedBuffer = await encryptAES(key, iv, outputBuffer);
  let base64EncryptedBuffer = btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedBuffer).slice(0, 16)));
  if (base64EncryptedBuffer.endsWith("==")) {
    base64EncryptedBuffer = base64EncryptedBuffer.slice(0, -2);
  }
  return base64EncryptedBuffer;
}

async function encryptAES(key, iv, data) {
  const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-CBC' },
      false,
      ['encrypt']
  );

  const encryptedBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: iv },
      cryptoKey,
      data
  );

  return encryptedBuffer;
}

async function decryptAES(key, iv, data) {
  const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-CBC' },
      false,
      ['encrypt', 'decrypt']
  );

  // Super annoying/weird thing here since the password was originally encrypted with no padding (and even though the data to be
  // encrypted is exactly equal to one block of 16 bytes) so we have to do some wizardry.
  // https://stackoverflow.com/questions/77432009/porting-node-js-crypto-code-to-subtlecrypto-webcrypto-fails-with-bad-decrypt 
  const encPaddingBlock = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: data }, cryptoKey, new Uint8Array());
  const cipherBufferPadded = concat(data, new Uint8Array(encPaddingBlock));

  const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: iv, length: 128 },
      cryptoKey,
      cipherBufferPadded
  );

  return new Uint8Array(decryptedBuffer);
}

function concat(a, b) { 
  const c = new (a.constructor)(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
}

async function tryDecodePassword(rawPassword) {
  try {
    // Base64 decoding
    const inputBuffer = Uint8Array.from(atob(rawPassword + "=="), c => c.charCodeAt(0));

    const key = new Uint8Array([22, 210, 29, 30, 134, 215, 228, 40, 196, 153, 254, 103, 184, 52, 88, 201]);
    const iv = new Uint8Array([128, 214, 58, 190, 150, 225, 47, 176, 184, 252, 245, 124, 237, 239, 20, 93]);

    let outputBuffer = await decryptAES(key, iv, inputBuffer);

    let userIdBytes = new Uint8Array(8);
    userIdBytes.set(outputBuffer.slice(0, 6));
    userIdBytes[5] &= 15; // Mask the last 4 bits

    const userId = convertBytesToBase36String(userIdBytes);

    const accessLevel = outputBuffer[5] >> 4 & 7;
    const timestamp = (outputBuffer[9] << 24 | outputBuffer[8] << 16 | outputBuffer[7] << 8 | outputBuffer[6]) * 2**32;
    const majorVersion = outputBuffer[10];
    const minorVersion = outputBuffer[11];
    const brand = outputBuffer[12] & 7;
    const userType = outputBuffer[12] >> 4 & 7;
    console.log(`Decoded password: userid = ${userId}, access = ${AccessLevel.getEnumByValue(accessLevel)}, expDate = ${ticksToDate(timestamp)}, majorVer = ${majorVersion}, minorVer = ${minorVersion}, brand = ${Brand.getEnumByValue(brand)}, userType = ${UserType.getEnumByValue(userType)}`);
    return true;
  } catch (error) {
    console.error(error);
    return false;
  }
}

class EnumBase {
  static getEnumByValue(value) {
    return Object.values(this).find(e => e.value == value);
  }
  
  static fillComboBox(comboBox) {
    const values = Object.values(this);
    values.forEach(level => {
      const option = document.createElement('option');
      option.value = level.value;
      option.text = level.name;
      comboBox.appendChild(option);
    });
  }
}

class AccessLevel extends EnumBase {
  static Diagnostic = new AccessLevel(0, "Diagnostic");
  static Service = new AccessLevel(1, "Service");
  static Programming = new AccessLevel(2, "Programming");
  static Development = new AccessLevel(3, "Development");
  static Customer = new AccessLevel(4, "Customer");
  static Reserved1 = new AccessLevel(5, "Reserved1");
  static Reserved2 = new AccessLevel(6, "Reserved2");
  static Reserved3 = new AccessLevel(7, "Reserved3");

  constructor(value, name) {
    super();
    this.value = value;
    this.name = name;
  }

  toString() {
    return this.name;
  }
}

class Brand extends EnumBase {
  static Hyster = new AccessLevel(0, "Hyster");
  static Yale = new AccessLevel(1, "Yale");
  static Utilev = new AccessLevel(2, "Utilev");
  static Generic = new AccessLevel(3, "Generic");
  static Customer = new AccessLevel(4, "Customer");
  static Reserved1 = new AccessLevel(5, "Reserved1");
  static Reserved2 = new AccessLevel(6, "Reserved2");
  static Reserved3 = new AccessLevel(7, "Reserved3");

  constructor(value, name) {
    super();
    this.value = value;
    this.name = name;
  }

  toString() {
    return this.name;
  }
}

class UserType extends EnumBase {
  static Development = new AccessLevel(0, "Development");
  static Service = new AccessLevel(1, "Service");
  static Customer1 = new AccessLevel(2, "Customer1");
  static Customer2 = new AccessLevel(3, "Customer2");
  static Customer3 = new AccessLevel(4, "Customer3");
  static Reserved1 = new AccessLevel(5, "Reserved1");
  static Reserved2 = new AccessLevel(6, "Reserved2");
  static Reserved3 = new AccessLevel(7, "Reserved3");

  constructor(value, name) {
    super();
    this.value = value;
    this.name = name;
  }

  toString() {
    return this.name;
  }
}
