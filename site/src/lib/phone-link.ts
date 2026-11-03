/**
 * Devuelve un enlace tel: solo cuando el directorio muestra un número único.
 * No intenta reconstruir códigos de área, identificar WhatsApp ni separar
 * listados ambiguos: eso podría conducir a otra persona u organización.
 * La función no realiza llamadas; el usuario decide desde su dispositivo.
 */
export function toDialHref(value: string | undefined): string | null {
  if (!value) return null;
  const original = value.trim();
  if (!original || original.includes("/") || /whatsapp/i.test(original)) return null;
  if (!/^\+?[\d ()-]+$/.test(original)) return null;
  const digits = original.replace(/[ ()-]/g, "");
  if (!/^\+?\d{8,15}$/.test(digits)) return null;
  return "tel:" + digits;
}
