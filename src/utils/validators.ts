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

/** Частичный CIDR: IP + необязательный / и цифры */
const IPV4_CIDR_PARTIAL = `${IPV4_PARTIAL}(/[0-9]{0,2})?`;
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

// Полный IP (IPv4/IPv6, CIDR, диапазон, список через запятую)
const IpFullSchema = z
  .string()
  .transform((v) => v.trim())
  .superRefine((value, ctx) => {
    if (!value) return; // пустая строка валидна на уровне обёртки
    if (!reIpFull.test(value)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Неверный IP-адрес",
      });
    }
  });

// Частичный IP (при вводе)
const IpPartialSchema = z.string().superRefine((value, ctx) => {
  const trimmed = value.trim();
  if (!trimmed) return; // пустое поле — ок

  // Не считаем валидным частичным вводом, если в любом из IP-токенов
  // (включая элементы диапазона и списка) есть 4 полных октета и лишняя
  // точка в конце: "33.33.33.33.", "33.33.33.33-22.22.22.22." и т.п.
  const items = value.split(",");
  for (const item of items) {
    const rangePart = item.split("-");
    for (const part of rangePart) {
      const t = part.trim();
      if (!t) continue;
      if (t.endsWith(".")) {
        const prefix = t.slice(0, -1).trim();
        if (reIpv4FullOnly.test(prefix)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Лишняя точка после полного IPv4",
          });
          return;
        }
      }
    }
  }

  // Базовая проверка по regex
  if (reIpPartial.test(value)) return;

  // Дополнительно допускаем случай, когда пользователь набрал IP и поставил
  // висящий дефис для диапазона: "192.168.1.1-".
  const noRightSpaces = value.replace(/\s+$/, "");
  if (noRightSpaces.endsWith("-")) {
    const prefix = noRightSpaces.slice(0, -1);
    if (prefix && reIpPartial.test(prefix)) {
      return;
    }
  }

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
 */
export function isIpPartiallyValid(value: string): boolean {
  return IpPartialSchema.safeParse(value).success;
}

// ==================== MAC ====================

const HEX2_RE = /^[0-9a-fA-F]{2}$/;
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

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];

      // Разрешаем пустой последний сегмент: "AA-BB-" и т.п.
      if (!part) {
        if (i !== parts.length - 1) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Пустой сегмент MAC в середине",
          });
          return;
        }
        continue;
      }

      if (!HEX1_2_RE.test(part)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Неверный hex в MAC",
        });
        return;
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

// Частичный список MAC при вводе
const MacPartialSchema = z.string().superRefine((value, ctx) => {
  const trimmed = value.trim();
  if (!trimmed) return; // пустое поле — ок

  const items = value.split(",");
  const lastIndex = items.length - 1;

  for (let i = 0; i < items.length; i++) {
    const raw = items[i];
    const token = raw.trim();

    // Последний пустой элемент: trailing comma ("AA-..-FF," или с пробелом) — ок
    if (i === lastIndex && !token) {
      return;
    }

    if (i < lastIndex) {
      if (!SingleMacFullSchema.safeParse(token).success) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Некорректный полный MAC до последнего элемента",
        });
        return;
      }
    } else {
      if (!SingleMacPartialSchema.safeParse(token).success) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Некорректный частичный MAC",
        });
        return;
      }
    }
  }
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
 */
export function isMacPartiallyValid(value: string): boolean {
  if (!value.trim()) return true;
  return MacPartialSchema.safeParse(value).success;
}
