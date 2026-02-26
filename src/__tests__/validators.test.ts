import {
  isIpPartiallyValid,
  isMacValid,
  isMacPartiallyValid,
  TEXT_ALLOWED_CHARS,
  TEXT_INVALID_SUBNET,
  TEXT_RANGE_ALLOWED,
  TEXT_RANGE_ORDER,
  TEXT_IP_VERSION_MISMATCH,
} from "../utils/validators";

// =====================================================================
//  IP — полная валидация
// =====================================================================

describe("isIpValid", () => {
  it("пустая строка — валидна", () => {
    expect(isIpPartiallyValid("")).toBe("");
    expect(isIpPartiallyValid("   ")).toBe("");
  });

  describe("IPv4", () => {
    it.each(["0.0.0.0", "192.168.1.1", "255.255.255.255", "10.0.0.1"])(
      "принимает %s",
      (v) => expect(isIpPartiallyValid(v)).toBe(""),
    );

    it.each(["256.0.0.1", "999.999.999.999", "1.2.3.4.5", "abc.def.ghi.jkl"])(
      "отклоняет %s",
      (v) => expect(isIpPartiallyValid(v)).not.toBe(""),
    );
  });

  describe("IPv6", () => {
    it.each([
      "::1",
      "::",
      "fe80::1",
      "2001:db8::1",
      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    ])("принимает %s", (v) => expect(isIpPartiallyValid(v)).toBe(""));

    it.each([
      "gggg::1",
      "12345::1",
      "2001:db8:::1",
      "2001:db8::1::1",
      "2001:db8:1:2:3:4:5",
      "2001:db8:1:2:3:4:5:6:7",
      "2001:db8:00000:1::1",
    ])("отклоняет %s", (v) => expect(isIpPartiallyValid(v)).not.toBe(""));
  });

  describe("CIDR", () => {
    it.each([
      "10.0.0.0/8",
      "192.168.0.0/24",
      "0.0.0.0/0",
      "255.255.255.255/32",
    ])("IPv4 CIDR: принимает %s", (v) =>
      expect(isIpPartiallyValid(v)).toBe(""),
    );

    it.each(["10.0.0.0/33", "192.168.1.1/33", "192.168.1/24"])(
      "IPv4 CIDR: отклоняет %s",
      (v) => expect(isIpPartiallyValid(v)).not.toBe(""),
    );

    it.each(["fe80::/10", "2001:db8::/32", "::1/128"])(
      "IPv6 CIDR: принимает %s",
      (v) => expect(isIpPartiallyValid(v)).toBe(""),
    );

    it.each(["::1/129", "2001:db8::/129"])("IPv6 CIDR: отклоняет %s", (v) =>
      expect(isIpPartiallyValid(v)).not.toBe(""),
    );
  });

  describe("Диапазон (через дефис)", () => {
    it.each(["192.168.1.1-192.168.1.10", "10.0.0.1 - 10.0.0.255"])(
      "IPv4 range: принимает %s",
      (v) => expect(isIpPartiallyValid(v)).toBe(""),
    );

    it("IPv4 range: отклоняет, если начало больше конца", () => {
      expect(isIpPartiallyValid("192.168.1.10-192.168.1.2")).not.toBe("");
    });

    it.each(["::1-::ffff", "2001:db8::1 - 2001:db8::ff"])(
      "IPv6 range: принимает %s",
      (v) => expect(isIpPartiallyValid(v)).toBe(""),
    );

    it("IPv6 range: отклоняет, если начало больше конца", () => {
      expect(isIpPartiallyValid("2001:db8::ff-2001:db8::1")).not.toBe("");
    });
  });

  describe("Перечисление через запятую", () => {
    it("принимает несколько IPv4", () => {
      expect(isIpPartiallyValid("192.168.1.1, 10.0.0.1")).toBe("");
    });

    it("принимает IPv4 + CIDR", () => {
      expect(isIpPartiallyValid("192.168.1.1, 10.0.0.0/24")).toBe("");
    });

    it("принимает IPv6 + IPv4", () => {
      expect(isIpPartiallyValid("::1, 192.168.1.1")).toBe("");
    });

    it("отклоняет trailing comma (на полной валидации)", () => {
      expect(isIpPartiallyValid("192.168.1.1,")).toBe("");
    });
  });
});

// =====================================================================
//  IP — частичная валидация (ввод)
// =====================================================================

describe("isIpPartiallyValid", () => {
  it.each([
    "",
    "1",
    "19",
    "192",
    "192.",
    "192.1",
    "192.168",
    "192.168.",
    "192.168.1",
    "192.168.1.",
    "192.168.1.1",
    "10.0.0.0/",
    "10.0.0.0/2",
    "10.0.0.0/24",
    "192.168.1.1-",
    "192.168.1.1-1",
    "2001:",
    "2001:db",
    "fe80::1",
    "192.168.1.1,",
    "192.168.1.1, ",
  ])("допускает частичный ввод: %s", (v) => {
    expect(isIpPartiallyValid(v)).toBe("");
  });

  it.each(["abc", "zzz.zzz"])("отклоняет явно некорректный: %s", (v) => {
    const expected =
      v === "zzz.zzz" ? TEXT_ALLOWED_CHARS : "Некорректный формат IP-адреса";

    expect(isIpPartiallyValid(v)).toBe(expected);
  });

  it("отклоняет список из чисел без IP", () => {
    expect(isIpPartiallyValid("12,22,22,22,22")).toBe(
      "Некорректный формат IP-адреса",
    );
  });

  it("отклоняет IPv4 CIDR с маской больше 32", () => {
    expect(isIpPartiallyValid("192.168.1.1/33")).toBe(TEXT_INVALID_SUBNET);
  });

  it("отклоняет IPv6 CIDR с маской больше 128", () => {
    expect(isIpPartiallyValid("2001:db8::/129")).toBe(TEXT_INVALID_SUBNET);
  });

  it("отклоняет IPv4 CIDR с неполным адресом", () => {
    expect(isIpPartiallyValid("192.168.1/24")).toBe(TEXT_INVALID_SUBNET);
  });

  it.each([
    "2001:db8:::1",
    "2001:db8::1::1",
    "2001:db8:1:2:3:4:5",
    "2001:db8:1:2:3:4:5:6:7",
    "2001:db8:00000:1::1",
  ])("отклоняет явно некорректный IPv6: %s", (v) =>
    expect(isIpPartiallyValid(v)).toBe("Некорректный формат IP-адреса"),
  );

  it("отклоняет некорректный диапазон с точкой перед дефисом", () => {
    expect(isIpPartiallyValid("192.168.1.-1")).toBe(TEXT_RANGE_ALLOWED);
  });

  it("отклоняет некорректный диапазон с точкой перед одиночным дефисом", () => {
    expect(isIpPartiallyValid("192.168.1.-")).toBe(TEXT_RANGE_ALLOWED);
  });

  it("отклоняет IPv4 диапазон, где начало больше конца", () => {
    expect(isIpPartiallyValid("192.168.1.10-192.168.1.2")).toBe(
      TEXT_RANGE_ORDER,
    );
  });

  it("отклоняет IPv6 диапазон, где начало больше конца", () => {
    expect(isIpPartiallyValid("2001:db8::ff-2001:db8::1")).toBe(
      TEXT_RANGE_ORDER,
    );
  });

  it("возвращает специальное сообщение для диапазона с разными версиями IP", () => {
    expect(isIpPartiallyValid("192.168.1.1-::1")).toBe(
      TEXT_IP_VERSION_MISMATCH,
    );
  });

  it("отклоняет IPv6 с тройным двоеточием", () => {
    expect(isIpPartiallyValid("2001:db8:::1")).toBe(
      "Некорректный формат IP-адреса",
    );
  });

  it("отклоняет IPv4 диапазон с двойным дефисом в конце", () => {
    expect(isIpPartiallyValid("12.33.33.33-12.33.33.33-")).toBe(
      TEXT_RANGE_ALLOWED,
    );
  });
});

// =====================================================================
//  MAC — полная валидация
// =====================================================================

describe("isMacValid", () => {
  it("пустая строка — валидна", () => {
    expect(isMacValid("")).toBe(true);
  });

  it.each(["AA-BB-CC-DD-EE-FF", "aa-bb-cc-dd-ee-ff", "01-23-45-67-89-AB"])(
    "принимает полный MAC: %s",
    (v) => expect(isMacValid(v)).toBe(true),
  );

  it.each([
    "AA-BB-CC-DD-EE", // 5 октетов
    "AA-BB-CC", // 3 октета
    "AA", // 1 октет
    "GG-HH-II-JJ-KK-LL", // невалидные hex
    "AA:BB:CC:DD:EE:FF", // двоеточие вместо дефиса
    "AABBCCDDEEFF", // без разделителей
  ])("отклоняет %s", (v) => expect(isMacValid(v)).toBe(false));

  it("принимает перечисление через запятую", () => {
    expect(isMacValid("AA-BB-CC-DD-EE-FF, 11-22-33-44-55-66")).toBe(true);
  });

  it("отклоняет trailing comma", () => {
    expect(isMacValid("AA-BB-CC-DD-EE-FF,")).toBe(false);
  });
});

// =====================================================================
//  MAC — частичная валидация (ввод)
// =====================================================================

describe("isMacPartiallyValid", () => {
  it.each([
    "",
    "A",
    "AA",
    "AA-",
    "AA-B",
    "AA-BB",
    "AA-BB-CC",
    "AA-BB-CC-DD",
    "AA-BB-CC-DD-EE",
    "AA-BB-CC-DD-EE-FF",
    "AA-BB-CC-DD-EE-FF,",
    "AA-BB-CC-DD-EE-FF, ",
  ])("допускает частичный ввод: %s", (v) => {
    expect(isMacPartiallyValid(v)).toBe("");
  });

  it.each(["GG", "ZZ-XX"])("отклоняет невалидный hex: %s", (v) =>
    expect(isMacPartiallyValid(v)).toBe(TEXT_ALLOWED_CHARS),
  );
});
