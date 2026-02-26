import { useState, useCallback, type ChangeEvent, type FormEvent } from "react";
import {
  isIpValid,
  isIpPartiallyValid,
  isMacValid,
  isMacPartiallyValid,
} from "../utils/validators";
import "./NetworkForm.css";

interface FieldState {
  value: string;
  touched: boolean; // пользователь покинул поле
  error: string | null; // текст ошибки (null = нет ошибки)
}

const INIT: FieldState = { value: "", touched: false, error: null };

export default function NetworkForm() {
  const [ip, setIp] = useState<FieldState>(INIT);
  const [mac, setMac] = useState<FieldState>(INIT);
  const [submitted, setSubmitted] = useState(false);

  /* ---------- IP ---------- */

  const handleIpChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value;
    const partial = isIpPartiallyValid(v);
    setIp((prev) => ({
      ...prev,
      value: v,
      error: v && !partial ? "Некорректный формат IP-адреса" : null,
    }));
  }, []);

  const handleIpBlur = useCallback(() => {
    setIp((prev) => {
      const full = isIpValid(prev.value);
      return {
        ...prev,
        touched: true,
        error: prev.value && !full ? "Некорректный IP-адрес" : null,
      };
    });
  }, []);

  /* ---------- MAC ---------- */

  const handleMacChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value;
    const partial = isMacPartiallyValid(v);
    setMac((prev) => ({
      ...prev,
      value: v,
      error: v && !partial ? "Некорректный формат MAC-адреса" : null,
    }));
  }, []);

  const handleMacBlur = useCallback(() => {
    setMac((prev) => {
      const full = isMacValid(prev.value);
      return {
        ...prev,
        touched: true,
        error: prev.value && !full ? "Некорректный MAC-адрес" : null,
      };
    });
  }, []);

  /* ---------- Submit ---------- */

  const handleSubmit = useCallback(
    (e: FormEvent) => {
      e.preventDefault();

      const ipOk = isIpValid(ip.value);
      const macOk = isMacValid(mac.value);

      setIp((prev) => ({
        ...prev,
        touched: true,
        error: prev.value && !ipOk ? "Некорректный IP-адрес" : null,
      }));
      setMac((prev) => ({
        ...prev,
        touched: true,
        error: prev.value && !macOk ? "Некорректный MAC-адрес" : null,
      }));

      if (ipOk && macOk) {
        setSubmitted(true);
        // Здесь можно отправить данные
        console.log("Submitted:", { ip: ip.value, mac: mac.value });
      }
    },
    [ip.value, mac.value],
  );

  return (
    <form className="network-form" onSubmit={handleSubmit} noValidate>
      <h2>Сетевые параметры</h2>

      {/* IP */}
      <div className={`field ${ip.error ? "field--error" : ""}`}>
        <label htmlFor="ip">IP-адрес</label>
        <input
          id="ip"
          type="text"
          placeholder="192.168.1.0/24, 10.0.0.1-10.0.0.5, fe80::1"
          value={ip.value}
          onChange={handleIpChange}
          onBlur={handleIpBlur}
          autoComplete="off"
          spellCheck={false}
        />
        {ip.error && <span className="field__error">{ip.error}</span>}
        <span className="field__hint">
          IPv4 / IPv6, CIDR, диапазон (через&nbsp;«‑»), перечисление через
          запятую
        </span>
      </div>

      {/* MAC */}
      <div className={`field ${mac.error ? "field--error" : ""}`}>
        <label htmlFor="mac">MAC-адрес</label>
        <input
          id="mac"
          type="text"
          placeholder="AA-BB-CC-DD-EE-FF"
          value={mac.value}
          onChange={handleMacChange}
          onBlur={handleMacBlur}
          autoComplete="off"
          spellCheck={false}
        />
        {mac.error && <span className="field__error">{mac.error}</span>}
        <span className="field__hint">
          Формат: XX-XX-XX-XX-XX-XX, перечисление через запятую
        </span>
      </div>

      <button type="submit">Отправить</button>

      {submitted && !ip.error && !mac.error && (
        <p className="success">Данные успешно отправлены ✓</p>
      )}
    </form>
  );
}
