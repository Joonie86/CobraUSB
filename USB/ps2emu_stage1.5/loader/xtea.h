code uint8_t xtea[596] =
{	0xCF, 0xC8, 0xD7, 0x5A, 0xFB, 0xE2, 0xD8, 0x67, 0xC8, 0xA4, 0x80, 0x7C, 0xA1, 0x76, 0xF4, 0x00, 
	0xBE, 0x48, 0xC4, 0x40, 0xA4, 0xFD, 0x3A, 0x84, 0xEF, 0xCF, 0x02, 0xFC, 0x8D, 0x0E, 0xD4, 0x80, 
	0x60, 0x7A, 0x7E, 0xBD, 0x0D, 0x75, 0x5F, 0x81, 0x12, 0x3F, 0xB2, 0x99, 0xE2, 0x25, 0x68, 0x0A, 
	0xD4, 0xD2, 0x22, 0x71, 0xAF, 0xA2, 0x25, 0x46, 0xFC, 0xE0, 0xC8, 0xB0, 0xA4, 0xBE, 0x50, 0xDC, 
	0x5F, 0xE6, 0x94, 0x23, 0x2E, 0xC4, 0x04, 0x1E, 0x3B, 0x9F, 0x80, 0x9E, 0x05, 0xB3, 0xAC, 0x38, 
	0xA1, 0x36, 0x84, 0xF8, 0x52, 0x48, 0xE4, 0x71, 0x62, 0x1B, 0xE3, 0x85, 0xCF, 0xD4, 0x8A, 0xD1, 
	0x4F, 0x78, 0x08, 0xA9, 0xA9, 0x68, 0x5C, 0xB8, 0x24, 0x38, 0x43, 0xA9, 0xF8, 0xA4, 0xD8, 0xD8, 
	0x84, 0x0E, 0xD9, 0x0A, 0xD4, 0xB8, 0x0A, 0x30, 0xC3, 0x24, 0x42, 0x79, 0xD5, 0x07, 0x46, 0x5D, 
	0xA1, 0x84, 0x40, 0x31, 0x93, 0xD4, 0x80, 0x14, 0xC8, 0xC4, 0x04, 0x62, 0x3B, 0xD5, 0xF8, 0xE6, 
	0xCC, 0xA4, 0x84, 0x44, 0xA1, 0x76, 0xD4, 0x78, 0x7B, 0xB7, 0xA5, 0x58, 0x6A, 0x39, 0x73, 0x03, 
	0xA7, 0xCC, 0xD4, 0xF8, 0x3E, 0xBA, 0x0E, 0x2F, 0xE1, 0x5A, 0x30, 0xB8, 0xDF, 0x59, 0x43, 0x2E, 
	0x79, 0xE6, 0x4C, 0xD8, 0x18, 0x67, 0xD9, 0x8D, 0x75, 0x80, 0xD2, 0x34, 0x79, 0x0F, 0x1A, 0xC0, 
	0x14, 0xF8, 0x76, 0xB0, 0x7A, 0xB7, 0x3C, 0x5A, 0x97, 0xD4, 0x18, 0x61, 0xA8, 0xC4, 0x24, 0x9A, 
	0x3A, 0xD5, 0x48, 0xAE, 0xCC, 0xA4, 0xAC, 0x0F, 0x5E, 0x89, 0xF9, 0xFC, 0x44, 0xB0, 0xEE, 0xCD, 
	0x5E, 0x3B, 0xD5, 0xC1, 0x99, 0xCC, 0xAC, 0xF8, 0x44, 0xEB, 0x0E, 0xA8, 0x9E, 0xA3, 0x62, 0xB8, 
	0x39, 0x9A, 0x11, 0xAC, 0x87, 0xE6, 0xEC, 0x5C, 0x98, 0x44, 0xA1, 0x09, 0x4B, 0x58, 0x1A, 0x34, 
	0x59, 0xDE, 0x76, 0x47, 0x6B, 0x02, 0xF2, 0xB3, 0xE7, 0x57, 0x3C, 0xE0, 0xEA, 0x2B, 0x4C, 0xB2, 
	0x49, 0xC4, 0x94, 0x89, 0x7A, 0xD5, 0x88, 0x0D, 0xAD, 0xA4, 0xFC, 0x38, 0xA9, 0x75, 0x72, 0x6B, 
	0xDB, 0x48, 0x44, 0xCF, 0xC3, 0x3B, 0x5D, 0x13, 0x27, 0xCC, 0x34, 0x6F, 0xA5, 0xA1, 0xEE, 0xEC, 
	0xA1, 0x5A, 0xE8, 0x8A, 0xA4, 0x62, 0x1B, 0xD5, 0xF8, 0xE6, 0xCC, 0xA4, 0x84, 0x44, 0xA0, 0xF6, 
	0xD2, 0x80, 0x5A, 0xB0, 0xE5, 0xDB, 0x33, 0x47, 0xDD, 0xFA, 0x40, 0x37, 0xC5, 0x84, 0xCC, 0x98, 
	0x36, 0xD4, 0x80, 0xA1, 0xE9, 0xC4, 0xBC, 0x1E, 0xA0, 0xF6, 0x80, 0x1D, 0x0D, 0xA4, 0x24, 0x38, 
	0x1C, 0x5D, 0xAC, 0x7B, 0xBB, 0x48, 0x6C, 0x58, 0x1C, 0x20, 0xAD, 0x84, 0x39, 0xFF, 0xDC, 0x7F, 
	0xC5, 0xA1, 0xE6, 0x2C, 0x81, 0x5A, 0x88, 0x8C, 0x24, 0x62, 0x9F, 0xED, 0xF2, 0xE6, 0xDC, 0xDC, 
	0x98, 0x44, 0x81, 0x09, 0x48, 0x68, 0x1A, 0x08, 0x59, 0x24, 0x0E, 0x03, 0xD5, 0xF8, 0xF6, 0xB7, 
	0x0C, 0x83, 0x64, 0x98, 0x16, 0xD4, 0x80, 0x26, 0x41, 0xC7, 0x82, 0x5A, 0xDA, 0xD5, 0x88, 0xDE, 
	0x0C, 0xA4, 0x84, 0x3D, 0xC1, 0x76, 0xF4, 0xFF, 0xDA, 0x08, 0x84, 0x59, 0x48, 0x39, 0xC1, 0x81, 
	0xCF, 0xCC, 0x84, 0xC4, 0xD8, 0xA1, 0x66, 0xA8, 0x9B, 0x12, 0xE6, 0xB8, 0x2F, 0x5B, 0x95, 0x9D, 
	0xF8, 0xE6, 0xC4, 0xD8, 0x4F, 0x7D, 0x0F, 0x4F, 0xBF, 0x80, 0x5B, 0x0A, 0xC4, 0xDB, 0xBA, 0x03, 
	0xB4, 0xF8, 0x96, 0xB3, 0x60, 0x77, 0x3C, 0xDE, 0x93, 0x2F, 0xF8, 0x11, 0xB7, 0x3A, 0x0D, 0x8A, 
	0x24, 0xD5, 0xF8, 0x0F, 0xF2, 0xA4, 0x84, 0x38, 0xA1, 0x3C, 0xAC, 0x78, 0x45, 0x48, 0xC4, 0x6C, 
	0x62, 0x3B, 0xFD, 0x84, 0x9D, 0x9E, 0xB0, 0xFB, 0x80, 0x52, 0x0E, 0xAB, 0x65, 0xA1, 0x30, 0x8F, 
	0xDB, 0x9C, 0x3E, 0x3D, 0xE7, 0xE6, 0xCC, 0x4D, 0xBA, 0x44, 0xA1, 0x0A, 0xD4, 0xCA, 0x22, 0xB0, 
	0xDB, 0x24, 0x62, 0xC3, 0xCB, 0xF8, 0xE6, 0xB3, 0x2E, 0x67, 0x3C, 0xDE, 0xFC, 0x3C, 0xC0, 0x1B, 
	0xD4, 0x3B, 0x78, 0x8A, 0x3A, 0xD5, 0x38, 0x0D, 0xAD, 0xA4, 0x0C, 0xAF, 0x20, 0x76, 0x44, 0xFC, 
	0x52, 0x4B, 0x62, 0xCF, 0xC3, 0x3B, 0x4D, 0x13, 0x27, 0xCC, 0x04, 0x6F, 0xA5, 0xA1, 0xDE, 0xEC, 
	0xA1, 0x5A, 0xF8, 0x8A, 0xA4, 0x62, 0x1B, 0xD5, 0xF8, 0xE6, 0xCC, 0xA4, 0x84, 0x44, 0xA0, 0xF6, 
	0xD1, 0x80, 0x5A, 
};