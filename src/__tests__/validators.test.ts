import {
  isIpValid,
  isIpPartiallyValid,
  isMacValid,
  isMacPartiallyValid,
} from "../utils/validators";

// =====================================================================
//  IP — полная валидация
// =====================================================================

describe("isIpValid", () => {
  it("пустая строка — валидна", () => {
    expect(isIpValid("")).toBe(true);
    expect(isIpValid("   ")).toBe(true);
  });

  describe("IPv4", () => {
    it.each([
      "0.0.0.0",
      "192.168.1.1",
      "255.255.255.255",
      "10.0.0.1",
    ])("принимает %s", (v) => expect(isIpValid(v)).toBe(true));

    it.each([
      "256.0.0.1",
      "999.999.999.999",
      "192.168.1",
      "1.2.3.4.5",
      "abc.def.ghi.jkl",
    ])("отклоняет %s", (v) => expect(isIpValid(v)).toBe(false));
  });

  describe("IPv6", () => {
    it.each([
      "::1",
      "::",
      "fe80::1",
      "2001:db8::1",
      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    ])("принимает %s", (v) => expect(isIpValid(v)).toBe(true));

    it.each(["gggg::1", "12345::1"])(
      "отклоняет %s",
      (v) => expect(isIpValid(v)).toBe(false),
    );
  });

  describe("CIDR", () => {
    it.each([
      "10.0.0.0/8",
      "192.168.0.0/24",
      "0.0.0.0/0",
      "255.255.255.255/32",
    ])("IPv4 CIDR: принимает %s", (v) => expect(isIpValid(v)).toBe(true));

    it.each(["10.0.0.0/33", "10.0.0.0/"])(
      "IPv4 CIDR: отклоняет %s",
      (v) => expect(isIpValid(v)).toBe(false),
    );

    it.each(["fe80::/10", "2001:db8::/32", "::1/128"])(
      "IPv6 CIDR: принимает %s",
      (v) => expect(isIpValid(v)).toBe(true),
    );

    it.each(["::1/129"])(
      "IPv6 CIDR: отклоняет %s",
      (v) => expect(isIpValid(v)).toBe(false),
    );
  });

  describe("Диапазон (через дефис)", () => {
    it.each([
      "192.168.1.1-192.168.1.10",
      "10.0.0.1 - 10.0.0.255",
    ])("IPv4 range: принимает %s", (v) => expect(isIpValid(v)).toBe(true));

    it.each(["::1-::ffff"])(
      "IPv6 range: принимает %s",
      (v) => expect(isIpValid(v)).toBe(true),
    );
  });

  describe("Перечисление через запятую", () => {
    it("принимает несколько IPv4", () => {
      expect(isIpValid("192.168.1.1, 10.0.0.1")).toBe(true);
    });

    it("принимает IPv4 + CIDR", () => {
      expect(isIpValid("192.168.1.1, 10.0.0.0/24")).toBe(true);
    });

    it("принимает IPv6 + IPv4", () => {
      expect(isIpValid("::1, 192.168.1.1")).toBe(true);
    });

    it("отклоняет trailing comma (на полной валидации)", () => {
      expect(isIpValid("192.168.1.1,")).toBe(false);
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

  it.each(["abc", "zzz.zzz"])(
    "отклоняет явно некорректный: %s",
    (v) => expect(isIpPartiallyValid(v)).not.toBe(""),
  );
});

// =====================================================================
//  MAC — полная валидация
// =====================================================================

describe("isMacValid", () => {
  it("пустая строка — валидна", () => {
    expect(isMacValid("")).toBe(true);
  });

  it.each([
    "AA-BB-CC-DD-EE-FF",
    "aa-bb-cc-dd-ee-ff",
    "01-23-45-67-89-AB",
  ])("принимает полный MAC: %s", (v) => expect(isMacValid(v)).toBe(true));

  it.each([
    "AA-BB-CC-DD-EE",       // 5 октетов
    "AA-BB-CC",             // 3 октета
    "AA",                   // 1 октет
    "GG-HH-II-JJ-KK-LL",  // невалидные hex
    "AA:BB:CC:DD:EE:FF",   // двоеточие вместо дефиса
    "AABBCCDDEEFF",         // без разделителей
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

  it.each(["GG", "ZZ-XX"])(
    "отклоняет невалидный hex: %s",
    (v) => expect(isMacPartiallyValid(v)).not.toBe(""),
  );
});
