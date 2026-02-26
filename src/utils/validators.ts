import { z } from "zod";

type ZodWithIpHelpers = typeof z & {
  ipv4?: () => z.ZodString;
  ipv6?: () => z.ZodString;
  cidrv4?: () => z.ZodString;
  cidrv6?: () => z.ZodString;
};

const zIp = z as ZodWithIpHelpers;

/* ------------------------------------------------------------------ */
/*  Общие текстовые сообщения валидации                               */
/* ------------------------------------------------------------------ */

export const TEXT_INVALID_SUBNET = "Неверно определена подсеть";
export const TEXT_INVALID_IP = "Некорректный IP-адрес";
export const TEXT_RANGE_ALLOWED = "Допустимый диапазон IPv4 или IPv6";
export const TEXT_RANGE_ORDER = "Неверный порядок IP в диапазоне";
export const TEXT_IP_VERSION_MISMATCH = "IP версии должны совпадать";
export const TEXT_ALLOWED_CHARS =
  'Поле может содержать только цифры, буквы "a-f", "A-F" и символы .:/,-';
export const TEXT_INVALID_MAC = "Некорректный MAC-адрес";

/* ------------------------------------------------------------------ */
/*  IP / MAC  validation helpers (на базе Zod)                        */
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

/** Частичный IPv6: разрешаем набираемые сегменты вроде "2001:", "fe80::1",
 *  но требуем наличие хотя бы одного двоеточия, чтобы отсечь строки вида "abc".
 */
const IPV6_PARTIAL = `(?=.*:)[0-9a-fA-F:]{1,39}`;

// ==================== CIDR ====================

const CIDR_SUFFIX_V4 = `/(3[0-2]|[12]\\d|\\d)`;
const CIDR_SUFFIX_V6 = `/(12[0-8]|1[01]\\d|\\d{1,2})`;

const IPV4_CIDR_FULL = `${IPV4_FULL}${CIDR_SUFFIX_V4}`;
const IPV6_CIDR_FULL = `${IPV6_FULL}${CIDR_SUFFIX_V6}`;

/** Частичный IPv4 CIDR: допускаем маску только после *полного* IPv4.
 *  Например, разрешаем "10.0.0.0/", "10.0.0.0/2", но не "192.168.1/24".
 */
const IPV4_CIDR_PARTIAL = `${IPV4_FULL}(/[0-9]{0,2})?`;
const IPV6_CIDR_PARTIAL = `${IPV6_PARTIAL}(/[0-9]{0,3})?`;

// ==================== Range (через дефис) ====================

const IPV4_RANGE_FULL = `${IPV4_FULL}\\s*-\\s*${IPV4_FULL}`;
const IPV6_RANGE_FULL = `${IPV6_FULL}\\s*-\\s*${IPV6_FULL}`;

/** Частичный диапазон: IP (возможно частичный) + необязательный " - IP",
 *  при этом допускаем висящий дефис в конце: "192.168.1.1-".
 */
const IPV4_RANGE_PARTIAL = `${IPV4_PARTIAL}(\\s*-\\s*${IPV4_PARTIAL}?)?`;
const IPV6_RANGE_PARTIAL = `${IPV6_PARTIAL}(\\s*-\\s*${IPV6_PARTIAL}?)?`;

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

// Атомарные Zod-схемы для *полных* IPv4/IPv6-токенов.
// Используем ip-хелперы zod, если они доступны в текущей версии, иначе
// fallback на regex-основанные схемы поверх наших шаблонов.
const Ipv4TokenSchema =
  typeof zIp.ipv4 === "function"
    ? zIp.ipv4()
    : z.string().regex(new RegExp(`^${IPV4_FULL}$`));

const Ipv6TokenSchema =
  typeof zIp.ipv6 === "function"
    ? zIp.ipv6()
    : z.string().regex(new RegExp(`^${IPV6_FULL}$`));

const Cidrv4TokenSchema =
  typeof zIp.cidrv4 === "function"
    ? zIp.cidrv4()
    : z.string().regex(new RegExp(`^${IPV4_CIDR_FULL}$`));

const Cidrv6TokenSchema =
  typeof zIp.cidrv6 === "function"
    ? zIp.cidrv6()
    : z.string().regex(new RegExp(`^${IPV6_CIDR_FULL}$`));

function isFullIpv4Token(value: string): boolean {
  return Ipv4TokenSchema.safeParse(value).success;
}

function isFullIpv6Token(value: string): boolean {
  return Ipv6TokenSchema.safeParse(value).success;
}

function isValidCidrV4Token(value: string): boolean {
  return Cidrv4TokenSchema.safeParse(value).success;
}

function isValidCidrV6Token(value: string): boolean {
  return Cidrv6TokenSchema.safeParse(value).success;
}

function ipv4ToNumber(ip: string): number {
  const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

function hasIpVersionMismatchInRange(value: string): boolean {
  const items = value.split(",");
  for (const item of items) {
    const rangeParts = item.split("-");
    if (rangeParts.length !== 2) continue;

    const left = rangeParts[0].trim();
    const right = rangeParts[1].trim();
    if (!left || !right) continue;

    const leftIsV6 = left.includes(":");
    const rightIsV6 = right.includes(":");
    if (leftIsV6 !== rightIsV6) {
      return true;
    }
  }
  return false;
}

function ipv6ToBigInt(ip: string): bigint {
  const hasDoubleColon = ip.includes("::");

  if (!hasDoubleColon) {
    const groups = ip.split(":");
    let result = 0n;
    for (const g of groups) {
      const value = BigInt(Number.parseInt(g, 16));
      result = (result << 16n) | value;
    }
    return result;
  }

  const [leftRaw, rightRaw] = ip.split("::");
  const leftParts = leftRaw ? leftRaw.split(":") : [];
  const rightParts = rightRaw ? rightRaw.split(":") : [];
  const missing = 8 - (leftParts.length + rightParts.length);

  const groups = [
    ...leftParts,
    ...Array(Math.max(missing, 0)).fill("0"),
    ...rightParts,
  ];

  let result = 0n;
  for (const g of groups) {
    const value = BigInt(Number.parseInt(g || "0", 16));
    result = (result << 16n) | value;
  }
  return result;
}

/**
 * Проверяет, содержит ли значение диапазон, в котором начальный IP
 * больше конечного (для IPv4 или IPv6). Возвращает true при нарушении порядка.
 */
function hasRangeOrderViolation(value: string): boolean {
  const items = value.split(",");
  for (const raw of items) {
    const rangeParts = raw.split("-");
    if (rangeParts.length !== 2) continue;

    const left = rangeParts[0].trim();
    const right = rangeParts[1].trim();
    if (!left || !right) continue;

    if (isFullIpv4Token(left) && isFullIpv4Token(right)) {
      if (ipv4ToNumber(left) > ipv4ToNumber(right)) {
        return true;
      }
    }

    if (isFullIpv6Token(left) && isFullIpv6Token(right)) {
      if (ipv6ToBigInt(left) > ipv6ToBigInt(right)) {
        return true;
      }
    }
  }
  return false;
}

function hasTrailingDotAfterFullIpv4(value: string): boolean {
  const items = value.split(",");
  for (const item of items) {
    const rangePart = item.split("-");
    for (const part of rangePart) {
      const t = part.trim();
      if (!t) continue;
      if (t.endsWith(".")) {
        const prefix = t.slice(0, -1).trim();
        if (isFullIpv4Token(prefix)) {
          return true;
        }
      }
    }
  }
  return false;
}

function isIpPartialAllowed(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return true; // пустое поле — ок

  if (hasTrailingDotAfterFullIpv4(value)) return false;

  // Не допускаем диапазоны, где левая часть заканчивается точкой,
  // а правая уже содержит какой-то ввод, например "192.168.1.-1".
  const items = value.split(",");
  for (const item of items) {
    const dashIndex = item.indexOf("-");
    if (dashIndex === -1) continue;

    const left = item.slice(0, dashIndex).trim();
    const right = item.slice(dashIndex + 1).trim();

    // Не допускаем ситуацию, когда левая часть диапазона заканчивается точкой,
    // независимо от того, есть ли правая часть ("192.168.1.-" или "192.168.1.-1").
    if (left.endsWith(".")) {
      return false;
    }

    // Не допускаем диапазоны вида "192.168.1-192.168.2.1" или
    // "192.168.1.1-192.168.2", где одна сторона — полный IPv4,
    // а другая содержит 1-2 точки (неполный IPv4).
    if (left && right) {
      const dotsLeft = (left.match(/\./g) || []).length;
      const dotsRight = (right.match(/\./g) || []).length;
      const leftFull = isFullIpv4Token(left);
      const rightFull = isFullIpv4Token(right);

      if (
        (leftFull && !rightFull && dotsRight > 0 && dotsRight < 3) ||
        (rightFull && !leftFull && dotsLeft > 0 && dotsLeft < 3)
      ) {
        return false;
      }
    }
  }

  // Если введён список через запятую, то все *завершённые* элементы
  // (кроме, возможно, последнего, который пользователь ещё набирает)
  // должны хотя бы выглядеть как IP/диапазон/CIDR: содержать '.', ':',
  // '/' или '-'. Это отсекает случаи вроде "12,22,22,22,22".
  if (items.length > 1) {
    const lastIndex = items.length - 1;
    for (let i = 0; i < lastIndex; i++) {
      const token = items[i].trim();
      if (!token) continue;
      if (
        !token.includes(".") &&
        !token.includes(":") &&
        !token.includes("/") &&
        !token.includes("-")
      ) {
        return false;
      }
    }
  }

  // Не допускаем тройное двоеточие в IPv6 даже при частичном вводе.
  if (value.includes(":::")) return false;

  // Не допускаем более одного "::" в одном IPv6-адресе, но при этом
  // разрешаем диапазоны и списки, где каждый адрес по отдельности
  // содержит не более одного сжатия (::1-2001:db8::1, ::1, 2001:db8::1).
  for (const item of items) {
    const rangeParts = item.split("-");
    for (const rangePart of rangeParts) {
      const cidrParts = rangePart.split("/");
      for (const part of cidrParts) {
        const t = part.trim();
        if (!t) continue;
        // IPv6-специфичные проверки применяем только к токенам с двоеточиями.
        if (!t.includes(":")) {
          continue;
        }

        // Разбор на группы.
        const groups = t.split(":");
        const nonEmpty = groups.filter((g) => g.length > 0).length;

        // Не допускаем адреса, которые начинаются с одиночного двоеточия
        // и далее содержат хотя бы одну непустую группу (" :2001:db8:... "),
        // но при этом не являются формой с "::" в начале.
        if (groups[0] === "" && nonEmpty >= 1 && !t.startsWith("::")) {
          return false;
        }

        // Не допускаем адреса, которые заканчиваются одиночным двоеточием
        // и содержат более одной непустой группы ("2001:db8:...:"),
        // но при этом не являются формой с "::" в конце.
        if (
          groups[groups.length - 1] === "" &&
          nonEmpty > 1 &&
          !t.endsWith("::")
        ) {
          return false;
        }

        // Любая IPv6-группа не должна содержать более 4 hex-символов.
        if (groups.some((g) => g.length > 4)) {
          return false;
        }

        const matches = t.match(/::/g);
        // Больше одного "::" — некорректно (например, 2001:db8::1::1)
        if (matches && matches.length > 1) {
          return false;
        }

        // Также отсеиваем случаи с "::" и семью или более непустыми группами,
        // например 2001:db8:...:1234::, которые считаем некорректными
        // в рамках нашей модели ввода.
        if (matches && nonEmpty >= 7) {
          return false;
        }

        // Специально отсеиваем случаи без "::" с заведомо некорректным
        // количеством полно заполненных групп:
        // - 7 полных групп (2001:db8:1:2:3:4:5)
        // - больше 8 полных групп (2001:db8:1:2:3:4:5:6:7)
        if (!matches || matches.length === 0) {
          if (nonEmpty === 7 || nonEmpty > 8) {
            return false;
          }
        }
      }
    }
  }

  // Специальная проверка IPv4 CIDR: если маска > 32 и IPv4-часть полная,
  // то даже частичный ввод считаем недопустимым (192.168.1.1/33 и т.п.).
  for (const item of items) {
    const rangeParts = item.split("-");
    for (const rangePart of rangeParts) {
      const cidrParts = rangePart.split("/");
      if (cidrParts.length < 2) continue;

      const ipPart = cidrParts[0].trim();
      const maskPart = cidrParts[1].trim();
      if (!maskPart) continue;
      if (!isFullIpv4Token(ipPart)) continue;

      const mask = Number.parseInt(maskPart, 10);
      if (Number.isFinite(mask) && mask > 32) {
        return false;
      }
    }
  }

  // Специальная проверка IPv6 CIDR: если маска > 128 и IPv6-часть полная,
  // то даже частичный ввод считаем недопустимым (2001:db8::/129 и т.п.).
  for (const item of items) {
    const rangeParts = item.split("-");
    for (const rangePart of rangeParts) {
      const cidrParts = rangePart.split("/");
      if (cidrParts.length < 2) continue;

      const ipPart = cidrParts[0].trim();
      const maskPart = cidrParts[1].trim();
      if (!maskPart) continue;
      if (!isFullIpv6Token(ipPart)) continue;

      const mask = Number.parseInt(maskPart, 10);
      if (Number.isFinite(mask) && mask > 128) {
        return false;
      }
    }
  }

  // Специальная проверка диапазона: начало не должно быть больше конца.
  if (hasRangeOrderViolation(value)) {
    return false;
  }

  // Специальная проверка: диапазон не может смешивать IPv4 и IPv6.
  if (hasIpVersionMismatchInRange(value)) {
    return false;
  }

  // Базовая проверка по regex
  if (reIpPartial.test(value)) return true;

  // Дополнительно допускаем случай, когда пользователь набрал IP и поставил
  // висящий дефис для диапазона: "192.168.1.1-".
  const noRightSpaces = value.replace(/\s+$/, "");
  if (noRightSpaces.endsWith("-")) {
    const prefix = noRightSpaces.slice(0, -1);
    // Разрешаем висящий дефис только после одиночного IP/списка IP,
    // но не после уже сформированного диапазона с дефисом внутри,
    // чтобы случаи вроде "12.33.33.33-12.33.33.33-" не считались валидными.
    if (prefix && !prefix.includes("-") && reIpPartial.test(prefix)) {
      return true;
    }
  }

  return false;
}

// Полный IP (IPv4/IPv6, CIDR, диапазон, список через запятую)
const IpFullSchema = z
  .string()
  .transform((v) => v.trim())
  .superRefine((value, ctx) => {
    if (!value) return; // пустая строка валидна на уровне обёртки

    const hasFullMatch = reIpFull.test(value);
    const hasTripleColon = value.includes(":::");

    if (!hasFullMatch || hasTripleColon) {
      ctx.addIssue({
        code: "custom",
        message: TEXT_INVALID_IP,
      });
      return;
    }

    // Дополнительная семантическая проверка CIDR-префиксов через z.cidrv4/z.cidrv6.
    // На этом этапе строка уже прошла базовый regex, здесь только уточняем корректность.
    const cidrRows = value.split(",");
    for (const raw of cidrRows) {
      const rangeParts = raw.split("-");
      for (const rangePart of rangeParts) {
        const t = rangePart.trim();
        if (!t || !t.includes("/")) continue;

        const hasColon = t.includes(":");
        const ok = hasColon ? isValidCidrV6Token(t) : isValidCidrV4Token(t);

        if (!ok) {
          ctx.addIssue({
            code: "custom",
            message: TEXT_INVALID_SUBNET,
          });
          return;
        }
      }
    }

    // Дополнительная семантическая проверка для IPv6-адресов с "::":
    // отклоняем варианты с семью и более непустыми группами, например
    // 2001:db8:...:1234::, даже если они формально проходят базовый regex.
    const rows = value.split(",");
    for (const raw of rows) {
      const rangeParts = raw.split("-");
      for (const rangePart of rangeParts) {
        const cidrParts = rangePart.split("/");
        for (const part of cidrParts) {
          const t = part.trim();
          if (!t || !t.includes(":")) continue;

          const groups = t.split(":");
          const nonEmpty = groups.filter((g) => g.length > 0).length;
          const matches = t.match(/::/g);

          if (matches && matches.length > 1) {
            ctx.addIssue({
              code: "custom",
              message: TEXT_INVALID_IP,
            });
            return;
          }

          if (matches && nonEmpty >= 7) {
            ctx.addIssue({
              code: "custom",
              message: TEXT_INVALID_IP,
            });
            return;
          }
        }
      }
    }

    // Дополнительная семантическая проверка диапазонов:
    // начало не должно быть больше конца.
    if (hasRangeOrderViolation(value)) {
      ctx.addIssue({
        code: "custom",
        message: TEXT_RANGE_ORDER,
      });
      return;
    }

    // Диапазон не может смешивать IPv4 и IPv6.
    if (hasIpVersionMismatchInRange(value)) {
      ctx.addIssue({
        code: "custom",
        message: TEXT_IP_VERSION_MISMATCH,
      });
      return;
    }
  });

/**
 * Проверяет, является ли строка корректным *полным* IP-значением
 * (IPv4/IPv6, CIDR, диапазон, список через запятую).
 */
export function isIpValid(value: string): boolean {
  if (!value.trim()) return true; // пустое поле — ок
  return IpFullSchema.safeParse(value).success;
}

/**
 * Проверяет, допустим ли *промежуточный* ввод IP-поля
 * (пока пользователь печатает).
 * Возвращает пустую строку при успехе и текст ошибки при неудаче.
 */
export function isIpPartiallyValid(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";

  // Любое полностью валидное значение автоматически считается
  // допустимым и для частичной валидации.
  if (isIpValid(value)) return "";

  // Сохраняем старую логику допуска через isIpPartialAllowed.
  if (isIpPartialAllowed(value)) return "";

  // ---- Формирование более конкретного сообщения об ошибке ----

  if (hasIpVersionMismatchInRange(value)) {
    return TEXT_IP_VERSION_MISMATCH;
  }

  // Недопустимые символы (не цифры, не A-F / a-f, не разделители).
  if (/[^0-9a-fA-F:.,\s/-]/.test(value)) {
    return TEXT_ALLOWED_CHARS;
  }

  // Проверка порядка диапазона: если обе части — полные IP одной версии
  // и начало больше конца, возвращаем специфичную ошибку порядка.
  if (hasRangeOrderViolation(value)) {
    return TEXT_RANGE_ORDER;
  }

  // Ошибка диапазона (есть дефис, но формат не прошёл partial-проверку).
  if (value.includes("-")) {
    return TEXT_RANGE_ALLOWED;
  }

  // Ошибка CIDR (есть '/', но маска некорректна).
  if (value.includes("/")) {
    return TEXT_INVALID_SUBNET;
  }

  // Общее сообщение по умолчанию.
  return "Некорректный формат IP-адреса";
}

// ==================== MAC ====================

// регулярка для ровно двух шестнадцатеричных символов
const HEX2_RE = /^[0-9a-fA-F]{2}$/;
// регулярка для одного или двух шестнадцатеричных символов
const HEX1_2_RE = /^[0-9a-fA-F]{1,2}$/;

// Полный одиночный MAC: XX-XX-XX-XX-XX-XX
const SingleMacFullSchema = z
  .string()
  .transform((s) => s.trim())
  .superRefine((t, ctx) => {
    if (!t) {
      ctx.addIssue({ code: "custom", message: TEXT_INVALID_MAC });
      return;
    }
    // Строго требуем формат XX-XX-XX-XX-XX-XX: 6 сегментов по 2 hex-символа.
    const parts = t.split("-");
    if (parts.length !== 6 || !parts.every((p) => HEX2_RE.test(p))) {
      ctx.addIssue({
        code: "custom",
        message: TEXT_INVALID_MAC,
      });
    }
  });

// Частичный одиночный MAC при вводе
const SingleMacPartialSchema = z
  .string()
  .transform((s) => s.trim())
  .superRefine((t, ctx) => {
    if (!t) return; // пустой токен внутри списка для последнего элемента обрабатываем отдельно

    const parts = t.split("-");
    if (parts.length > 6) {
      ctx.addIssue({
        code: "custom",
        message: "Слишком много сегментов MAC",
      });
      return;
    }

    const lastIndex = parts.length - 1;

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];

      // Разрешаем пустой последний сегмент: "AA-BB-" и т.п.
      if (!part) {
        if (i !== lastIndex) {
          ctx.addIssue({
            code: "custom",
            message: "Пустой сегмент MAC в середине",
          });
          return;
        }
        continue;
      }

      // Для всех сегментов, кроме последнего, требуем ровно 2 hex-символа.
      // Для последнего сегмента допускаем 1–2 hex-символа (пользователь допечатывает).
      if (i < lastIndex) {
        if (!HEX2_RE.test(part)) {
          ctx.addIssue({
            code: "custom",
            message: "Неверный hex в MAC",
          });
          return;
        }
      } else {
        if (!HEX1_2_RE.test(part)) {
          ctx.addIssue({
            code: "custom",
            message: "Неверный hex в MAC",
          });
          return;
        }
      }
    }
  });

// Полный список MAC через запятую
const MacFullSchema = z.string().superRefine((value, ctx) => {
  const trimmed = value.trim();
  if (!trimmed) return; // пустое поле — ок на уровне обёртки

  const items = value.split(",");
  for (const raw of items) {
    const token = raw.trim();
    if (!token) {
      // пустой элемент (в т.ч. trailing comma) — ошибка
      ctx.addIssue({
        code: "custom",
        message: TEXT_INVALID_MAC,
      });
      return;
    }
    if (!SingleMacFullSchema.safeParse(token).success) {
      ctx.addIssue({
        code: "custom",
        message: TEXT_INVALID_MAC,
      });
      return;
    }
  }
});

function isMacPartialAllowed(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return true; // пустое поле — ок

  const items = value.split(",");
  const lastIndex = items.length - 1;

  for (let i = 0; i < items.length; i++) {
    const raw = items[i];
    const token = raw.trim();

    // Последний пустой элемент: trailing comma ("AA-..-FF," или с пробелом) — ок
    if (i === lastIndex && !token) {
      return true;
    }

    if (i < lastIndex) {
      if (!SingleMacFullSchema.safeParse(token).success) {
        return false;
      }
    } else {
      if (!SingleMacPartialSchema.safeParse(token).success) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Полная валидация MAC (при сабмите).
 * Все элементы списка через запятую должны быть полными MAC.
 */
export function isMacValid(value: string): boolean {
  if (!value.trim()) return true;
  return MacFullSchema.safeParse(value).success;
}

/**
 * Частичная валидация MAC (при вводе).
 * Все элементы до последнего — полные MAC,
 * последний — может быть частичным (пользователь его набирает).
 * Разрешаем завершающую запятую и пробелы после неё.
 * Возвращает пустую строку при успехе и текст ошибки при неудаче.
 */
export function isMacPartiallyValid(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";

  // Любое полностью валидное значение автоматически считается
  // допустимым и для частичной валидации.
  if (isMacValid(value)) return "";

  // Сохраняем старую логику допуска через isMacPartialAllowed.
  if (isMacPartialAllowed(value)) return "";

  // ---- Формирование более конкретного сообщения об ошибке ----

  // Недопустимые символы (не цифры, не A-F / a-f, не '-', не ',').
  if (/[^0-9a-fA-F,\s-]/.test(value)) {
    return TEXT_ALLOWED_CHARS;
  }

  // Ошибка списка MAC (что-то не так с разделением через запятую).
  if (value.includes(",")) {
    return "Некорректный формат списка MAC-адресов";
  }

  // Общее сообщение по умолчанию.
  return TEXT_INVALID_MAC;
}
