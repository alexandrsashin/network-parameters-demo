import { z } from "zod";

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
const reIpv4FullOnly = new RegExp(`^${IPV4_FULL}$`);
const reIpv6FullOnly = new RegExp(`^${IPV6_FULL}$`);

function ipv4ToNumber(ip: string): number {
  const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
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
        if (reIpv4FullOnly.test(prefix)) {
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

        // Любая IPv6-группа не должна содержать более 4 hex-символов.
        const groups = t.split(":");
        if (groups.some((g) => g.length > 4)) {
          return false;
        }

        const matches = t.match(/::/g);
        // Больше одного "::" — некорректно (например, 2001:db8::1::1)
        if (matches && matches.length > 1) {
          return false;
        }

        // Специально отсеиваем случаи без "::" с заведомо некорректным
        // количеством полно заполненных групп:
        // - 7 полных групп (2001:db8:1:2:3:4:5)
        // - больше 8 полных групп (2001:db8:1:2:3:4:5:6:7)
        if (!matches || matches.length === 0) {
          const nonEmpty = groups.filter((g) => g.length > 0).length;
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
      if (!reIpv4FullOnly.test(ipPart)) continue;

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
      if (!reIpv6FullOnly.test(ipPart)) continue;

      const mask = Number.parseInt(maskPart, 10);
      if (Number.isFinite(mask) && mask > 128) {
        return false;
      }
    }
  }

  // Специальная проверка IPv4 диапазона: если обе части — полные IPv4 и
  // начало диапазона больше конца, такой диапазон считаем недопустимым
  // даже при частичном вводе.
  for (const item of items) {
    const rangeParts = item.split("-");
    if (rangeParts.length !== 2) continue;

    const left = rangeParts[0].trim();
    const right = rangeParts[1].trim();
    if (!left || !right) continue;

    if (reIpv4FullOnly.test(left) && reIpv4FullOnly.test(right)) {
      const start = ipv4ToNumber(left);
      const end = ipv4ToNumber(right);
      if (start > end) {
        return false;
      }
    }
  }

  // Базовая проверка по regex
  if (reIpPartial.test(value)) return true;

  // Дополнительно допускаем случай, когда пользователь набрал IP и поставил
  // висящий дефис для диапазона: "192.168.1.1-".
  const noRightSpaces = value.replace(/\s+$/, "");
  if (noRightSpaces.endsWith("-")) {
    const prefix = noRightSpaces.slice(0, -1);
    if (prefix && reIpPartial.test(prefix)) {
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
        code: z.ZodIssueCode.custom,
        message: "Неверный IP-адрес",
      });
      return;
    }

    // Дополнительная семантическая проверка для IPv4-диапазонов:
    // начало не должно быть больше конца (по числовому сравнению октетов).
    const items = value.split(",");
    for (const raw of items) {
      const token = raw.trim();
      if (!token.includes("-")) continue;

      const [leftRaw, rightRaw] = token.split("-");
      if (!leftRaw || !rightRaw) continue;
      const left = leftRaw.trim();
      const right = rightRaw.trim();

      if (reIpv4FullOnly.test(left) && reIpv4FullOnly.test(right)) {
        const start = ipv4ToNumber(left);
        const end = ipv4ToNumber(right);
        if (start > end) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Начало диапазона IPv4 больше конца",
          });
          return;
        }
      }
    }
  });

// Частичный IP (при вводе)
const IpPartialSchema = z.string().superRefine((value, ctx) => {
  if (isIpPartialAllowed(value)) return;

  ctx.addIssue({
    code: z.ZodIssueCode.custom,
    message: "Неверный IP (частичный ввод)",
  });
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

  // Недопустимые символы (не цифры, не A-F / a-f, не разделители).
  if (/[^0-9a-fA-F:.,\s\/-]/.test(value)) {
    return "Содержатся недопустимые символы в IP-адресе";
  }

  // Ошибка диапазона (есть дефис, но формат не прошёл partial-проверку).
  if (value.includes("-")) {
    return "Некорректный формат диапазона IP-адресов";
  }

  // Ошибка CIDR (есть '/', но маска некорректна).
  if (value.includes("/")) {
    return "Некорректный формат CIDR-префикса IP-адреса";
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
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Пустой MAC" });
      return;
    }

    const parts = t.split("-");
    if (parts.length !== 6 || !parts.every((p) => HEX2_RE.test(p))) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Некорректный MAC",
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
        code: z.ZodIssueCode.custom,
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
            code: z.ZodIssueCode.custom,
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
            code: z.ZodIssueCode.custom,
            message: "Неверный hex в MAC",
          });
          return;
        }
      } else {
        if (!HEX1_2_RE.test(part)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
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
        code: z.ZodIssueCode.custom,
        message: "Пустой элемент в списке MAC",
      });
      return;
    }
    if (!SingleMacFullSchema.safeParse(token).success) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Некорректный MAC в списке",
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

// Частичный список MAC при вводе
const MacPartialSchema = z.string().superRefine((value, ctx) => {
  if (isMacPartialAllowed(value)) return;

  ctx.addIssue({
    code: z.ZodIssueCode.custom,
    message: "Некорректный MAC (частичный ввод)",
  });
});

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
    return "Содержатся недопустимые символы в MAC-адресе";
  }

  // Ошибка списка MAC (что-то не так с разделением через запятую).
  if (value.includes(",")) {
    return "Некорректный формат списка MAC-адресов";
  }

  // Общее сообщение по умолчанию.
  return "Некорректный формат MAC-адреса";
}
