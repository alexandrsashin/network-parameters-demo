import { useState, useCallback, type ChangeEvent, type FormEvent } from "react";
import {
  isIpPartiallyValid,
  isMacPartiallyValid,
  isMacValid,
  TEXT_INVALID_IP,
  TEXT_INVALID_MAC,
  TEXT_RANGE_ALLOWED,
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
    const partialError = isIpPartiallyValid(v);
    setIp((prev) => {
      let error: string | null = null;
      if (v && partialError) {
        error = partialError;
      }
      return { ...prev, value: v, error };
    });
  }, []);

  const handleIpBlur = useCallback(() => {
    setIp((prev) => {
      const partialError = isIpPartiallyValid(prev.value);
      return {
        ...prev,
        touched: true,
        error: prev.value && partialError ? partialError : null,
      };
    });
  }, []);

  /* ---------- MAC ---------- */

  const handleMacChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value;
    const partialError = isMacPartiallyValid(v);
    setMac((prev) => {
      let error: string | null = null;
      if (v && partialError) {
        error = partialError;
      }
      return { ...prev, value: v, error };
    });
  }, []);

  const handleMacBlur = useCallback(() => {
    setMac((prev) => {
      const partialError = isMacPartiallyValid(prev.value);
      let error: string | null = null;

      if (prev.value) {
        if (partialError) {
          error = partialError;
        } else if (!isMacValid(prev.value)) {
          error = TEXT_INVALID_MAC;
        }
      }

      return { ...prev, touched: true, error };
    });
  }, []);

  /* ---------- Submit ---------- */

  const handleSubmit = useCallback(
    (e: FormEvent) => {
      e.preventDefault();

      const ipOk = isIpPartiallyValid(ip.value) === "";
      const macPartialOk = isMacPartiallyValid(mac.value) === "";
      const macFullOk = !mac.value || isMacValid(mac.value);
      const macOk = macPartialOk && macFullOk;

      setIp((prev) => ({
        ...prev,
        touched: true,
        error: prev.value && !ipOk ? TEXT_INVALID_IP : null,
      }));
      setMac((prev) => ({
        ...prev,
        touched: true,
        error: prev.value && !macOk ? TEXT_INVALID_MAC : null,
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
          запятую. {TEXT_RANGE_ALLOWED}
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
