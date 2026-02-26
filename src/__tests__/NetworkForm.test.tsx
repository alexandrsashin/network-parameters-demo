import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import NetworkForm from "../components/NetworkForm";

function setup() {
  const user = userEvent.setup();
  render(<NetworkForm />);
  const ipInput = screen.getByLabelText("IP-адрес");
  const macInput = screen.getByLabelText("MAC-адрес");
  const submitBtn = screen.getByRole("button", { name: /отправить/i });
  return { user, ipInput, macInput, submitBtn };
}

// =====================================================================
//  Рендеринг
// =====================================================================

describe("NetworkForm — рендеринг", () => {
  it("рендерит заголовок", () => {
    render(<NetworkForm />);
    expect(screen.getByText("Сетевые параметры")).toBeInTheDocument();
  });

  it("рендерит поля IP и MAC", () => {
    const { ipInput, macInput } = setup();
    expect(ipInput).toBeInTheDocument();
    expect(macInput).toBeInTheDocument();
  });

  it("рендерит кнопку «Отправить»", () => {
    const { submitBtn } = setup();
    expect(submitBtn).toBeInTheDocument();
  });

  it("не показывает ошибки по умолчанию", () => {
    setup();
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });
});

// =====================================================================
//  IP-поле — валидация
// =====================================================================

describe("NetworkForm — IP валидация", () => {
  it("принимает корректный IPv4 без ошибок", async () => {
    const { user, ipInput } = setup();
    await user.type(ipInput, "192.168.1.1");
    await user.tab(); // blur
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });

  it("принимает IPv4 CIDR без ошибок", async () => {
    const { user, ipInput } = setup();
    await user.type(ipInput, "10.0.0.0/24");
    await user.tab();
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });

  it("принимает IPv6 без ошибок", async () => {
    const { user, ipInput } = setup();
    await user.type(ipInput, "fe80::1");
    await user.tab();
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });

  it("принимает диапазон IPv4 без ошибок", async () => {
    const { user, ipInput } = setup();
    await user.type(ipInput, "192.168.1.1-192.168.1.5");
    await user.tab();
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });

  it("принимает перечисление через запятую без ошибок", async () => {
    const { user, ipInput } = setup();
    await user.type(ipInput, "192.168.1.1, 10.0.0.1");
    await user.tab();
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });

  it("показывает ошибку при некорректном IP по blur", async () => {
    const { user, ipInput } = setup();
    await user.type(ipInput, "abc.def");
    await user.tab();
    expect(screen.getByText(/некорректный формат ip/i)).toBeInTheDocument();
  });

  it("показывает ошибку при вводе невалидных символов", async () => {
    const { user, ipInput } = setup();
    await user.type(ipInput, "xyz!");
    expect(
      screen.getByText(/содержатся недопустимые символы в ip-адресе/i),
    ).toBeInTheDocument();
  });

  it("убирает ошибку когда пользователь исправляет ввод", async () => {
    const { user, ipInput } = setup();
    await user.type(ipInput, "abc.def");
    await user.tab();
    expect(screen.getByText(/некорректный формат ip/i)).toBeInTheDocument();

    await user.clear(ipInput);
    await user.type(ipInput, "192.168.1.1");
    await user.tab();
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });

  it("не показывает ошибку при частичном но корректном вводе после blur", async () => {
    const { user, ipInput } = setup();
    await user.type(ipInput, "abc.def");
    await user.tab(); // blur -> touched
    expect(screen.getByText(/некорректный формат ip/i)).toBeInTheDocument();

    await user.clear(ipInput);
    await user.type(ipInput, "192.168");
    // частичный ввод с верным форматом — ошибки нет
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });

  it("убирает ошибку сразу на onChange когда ввод становится валидным", async () => {
    const { user, ipInput } = setup();
    await user.type(ipInput, "bad");
    await user.tab();
    expect(screen.getByText(/некорректный формат ip/i)).toBeInTheDocument();

    await user.clear(ipInput);
    await user.type(ipInput, "10.0.0.1");
    // ошибка исчезает сразу, без blur
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });
});

// =====================================================================
//  MAC-поле — валидация
// =====================================================================

describe("NetworkForm — MAC валидация", () => {
  it("принимает корректный MAC без ошибок", async () => {
    const { user, macInput } = setup();
    await user.type(macInput, "AA-BB-CC-DD-EE-FF");
    await user.tab();
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });

  it("принимает перечисление MAC через запятую", async () => {
    const { user, macInput } = setup();
    await user.type(macInput, "AA-BB-CC-DD-EE-FF, 11-22-33-44-55-66");
    await user.tab();
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });

  it("показывает ошибку при неполном MAC по blur", async () => {
    const { user, macInput } = setup();
    await user.type(macInput, "AA-BB-CC");
    await user.tab();
    expect(screen.getByText(/некорректный mac/i)).toBeInTheDocument();
  });

  it("показывает ошибку при невалидных hex-символах", async () => {
    const { user, macInput } = setup();
    await user.type(macInput, "GG");
    expect(
      screen.getByText(/содержатся недопустимые символы в mac-адресе/i),
    ).toBeInTheDocument();
  });

  it("не показывает ошибку при частичном вводе MAC", async () => {
    const { user, macInput } = setup();
    await user.type(macInput, "AA-BB");
    // Не blur — частичный ввод допустим
    expect(
      screen.queryByText(/некорректный формат mac/i),
    ).not.toBeInTheDocument();
  });

  it("не показывает ошибку при частичном но корректном вводе MAC после blur", async () => {
    const { user, macInput } = setup();
    await user.type(macInput, "AA-BB");
    await user.tab(); // blur -> touched
    expect(screen.getByText(/некорректный mac/i)).toBeInTheDocument();

    await user.clear(macInput);
    await user.type(macInput, "AA-BB-CC");
    // частичный ввод с верным форматом — ошибки нет
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });

  it("убирает ошибку MAC сразу на onChange когда ввод валиден", async () => {
    const { user, macInput } = setup();
    await user.type(macInput, "AA-BB");
    await user.tab();
    expect(screen.getByText(/некорректный mac/i)).toBeInTheDocument();

    await user.clear(macInput);
    await user.type(macInput, "AA-BB-CC-DD-EE-FF");
    expect(screen.queryByText(/некорректный/i)).not.toBeInTheDocument();
  });
});

// =====================================================================
//  Сабмит
// =====================================================================

describe("NetworkForm — сабмит", () => {
  it("показывает успех при отправке с валидными данными", async () => {
    const { user, ipInput, macInput, submitBtn } = setup();
    await user.type(ipInput, "192.168.1.1");
    await user.type(macInput, "AA-BB-CC-DD-EE-FF");
    await user.click(submitBtn);
    expect(screen.getByText(/данные успешно отправлены/i)).toBeInTheDocument();
  });

  it("показывает успех при отправке пустых полей (оба необязательны)", async () => {
    const { user, submitBtn } = setup();
    await user.click(submitBtn);
    expect(screen.getByText(/данные успешно отправлены/i)).toBeInTheDocument();
  });

  it("не показывает успех при невалидном IP", async () => {
    const { user, ipInput, submitBtn } = setup();
    await user.type(ipInput, "abc.def");
    await user.click(submitBtn);
    expect(
      screen.queryByText(/данные успешно отправлены/i),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/некорректный ip/i)).toBeInTheDocument();
  });

  it("не показывает успех при невалидном MAC", async () => {
    const { user, macInput, submitBtn } = setup();
    await user.type(macInput, "AA-BB");
    await user.click(submitBtn);
    expect(
      screen.queryByText(/данные успешно отправлены/i),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/некорректный mac/i)).toBeInTheDocument();
  });

  it("показывает ошибки для обоих полей при невалидных данных", async () => {
    const { user, ipInput, macInput, submitBtn } = setup();
    await user.type(ipInput, "999.999.999.999");
    await user.type(macInput, "ZZ-XX-YY-WW-VV-UU");
    await user.click(submitBtn);
    expect(screen.getByText(/некорректный ip/i)).toBeInTheDocument();
    expect(screen.getByText(/некорректный mac/i)).toBeInTheDocument();
  });
});
