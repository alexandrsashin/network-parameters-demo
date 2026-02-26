/* ------------------------------------------------------------------ */
/*  IP / MAC  validation helpers                                      */
/*  Поддерживают частичный ввод (пока пользователь печатает)          */
/*  и полный ввод (при сабмите / блёре)                               */
/* ------------------------------------------------------------------ */

// ==================== IPv4 ====================

/** Полный октет 0-255 */
const OCTET = `(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d)`;

/** Полный IPv4 */
const IPV4_FULL = `${OCTET}(\\.${OCTET}){3}`;

/** Частичный IPv4: допускаем неполный ввод октетов,
 *  например "192.", "192.168", "192.168.1." */
const IPV4_PARTIAL = `${OCTET}(\\.${OCTET}){0,2}(\\.${OCTET}?\\.?)?`;

// ==================== IPv6 ====================

const H16 = `[0-9a-fA-F]{1,4}`;

/** Упрощённая проверка полного IPv6 (стандартная + сжатая формы) */
const IPV6_FULL =
  `(` +
  `(${H16}:){7}${H16}` + // 1:2:3:4:5:6:7:8
  `|(${H16}:){1,7}:` + // 1::  …  1:2:3:4:5:6:7::
  `|(${H16}:){1,6}:${H16}` + // 1::8  …  1:2:3:4:5:6::8
  `|(${H16}:){1,5}(:${H16}){1,2}` +
  `|(${H16}:){1,4}(:${H16}){1,3}` +
  `|(${H16}:){1,3}(:${H16}){1,4}` +
  `|(${H16}:){1,2}(:${H16}){1,5}` +
  `|${H16}:(:${H16}){1,6}` +
  `|:(:${H16}){1,7}` +
  `|::` +
  `)`;

/** Частичный IPv6: разрешаем набираемые сегменты вроде "2001:", "fe80::1" */
const IPV6_PARTIAL = `[0-9a-fA-F:]{1,39}`;

// ==================== CIDR ====================

const CIDR_SUFFIX_V4 = `/(3[0-2]|[12]\\d|\\d)`;
const CIDR_SUFFIX_V6 = `/(12[0-8]|1[01]\\d|\\d{1,2})`;

const IPV4_CIDR_FULL = `${IPV4_FULL}${CIDR_SUFFIX_V4}`;
const IPV6_CIDR_FULL = `${IPV6_FULL}${CIDR_SUFFIX_V6}`;

/** Частичный CIDR: IP + необязательный / и цифры */
const IPV4_CIDR_PARTIAL = `${IPV4_PARTIAL}(/[0-9]{0,2})?`;
const IPV6_CIDR_PARTIAL = `${IPV6_PARTIAL}(/[0-9]{0,3})?`;

// ==================== Range (через дефис) ====================

const IPV4_RANGE_FULL = `${IPV4_FULL}\\s*-\\s*${IPV4_FULL}`;
const IPV6_RANGE_FULL = `${IPV6_FULL}\\s*-\\s*${IPV6_FULL}`;

/** Частичный диапазон: IP (возможно частичный) + необязательный " - IP" */
const IPV4_RANGE_PARTIAL = `${IPV4_PARTIAL}(\\s*-\\s*${IPV4_PARTIAL})?`;
const IPV6_RANGE_PARTIAL = `${IPV6_PARTIAL}(\\s*-\\s*${IPV6_PARTIAL})?`;

// ==================== Единые (single token) ====================

/** Полный одиночный IP-токен: IPv4, IPv6, с CIDR или диапазон */
const SINGLE_FULL =
  `(` +
  `${IPV4_CIDR_FULL}|${IPV4_RANGE_FULL}|${IPV4_FULL}` +
  `|${IPV6_CIDR_FULL}|${IPV6_RANGE_FULL}|${IPV6_FULL}` +
  `)`;

const SINGLE_PARTIAL =
  `(` +
  `${IPV4_CIDR_PARTIAL}|${IPV4_RANGE_PARTIAL}` +
  `|${IPV6_CIDR_PARTIAL}|${IPV6_RANGE_PARTIAL}` +
  `)`;

// ==================== Comma-separated list ====================

/** Полный: одно или несколько значений через запятую */
const FULL_LIST = `^\\s*${SINGLE_FULL}(\\s*,\\s*${SINGLE_FULL})*\\s*$`;

/** Частичный (при вводе): разрешаем trailing comma, пробелы и т.д. */
const PARTIAL_LIST = `^\\s*${SINGLE_PARTIAL}(\\s*,\\s*${SINGLE_PARTIAL})*(\\s*,\\s*)?\\s*$`;

// ==================== Public API: IP ====================

const reIpFull = new RegExp(FULL_LIST);
const reIpPartial = new RegExp(PARTIAL_LIST);

/**
 * Проверяет, является ли строка корректным *полным* IP-значением
 * (IPv4/IPv6, CIDR, диапазон, список через запятую).
 */
export function isIpValid(value: string): boolean {
  if (!value.trim()) return true; // пустое поле — ок
  return reIpFull.test(value);
}

/**
 * Проверяет, допустим ли *промежуточный* ввод IP-поля
 * (пока пользователь печатает).
 */
export function isIpPartiallyValid(value: string): boolean {
  if (!value.trim()) return true;
  return reIpPartial.test(value);
}

// ==================== MAC ====================

/** Полный MAC: XX-XX-XX-XX-XX-XX (дефис-разделитель) */
const MAC_SEP = `-`;
const HEX2 = `[0-9a-fA-F]{2}`;
const MAC_FULL = `${HEX2}(${MAC_SEP}${HEX2}){5}`;

/** Частичный MAC: допускаем неполный ввод, например "AA", "AA-B", "AA-BB-" */
const MAC_PARTIAL = `[0-9a-fA-F]{1,2}(${MAC_SEP}[0-9a-fA-F]{0,2}){0,5}`;

/** Список MAC через запятую — полный */
const MAC_FULL_LIST = `^\\s*${MAC_FULL}(\\s*,\\s*${MAC_FULL})*\\s*$`;

/** Список MAC через запятую — частичный (при вводе) */
const MAC_PARTIAL_LIST = `^\\s*${MAC_PARTIAL}(\\s*,\\s*${MAC_PARTIAL})*(\\s*,\\s*)?\\s*$`;

const reMacFull = new RegExp(MAC_FULL_LIST);
const reMacPartial = new RegExp(MAC_PARTIAL_LIST);

/**
 * Полная валидация MAC (при сабмите).
 */
export function isMacValid(value: string): boolean {
  if (!value.trim()) return true;
  return reMacFull.test(value);
}

/**
 * Частичная валидация MAC (при вводе).
 */
export function isMacPartiallyValid(value: string): boolean {
  if (!value.trim()) return true;
  return reMacPartial.test(value);
}
