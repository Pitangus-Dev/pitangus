// React Flow measures its nodes in the browser: jsdom needs these to lay them out (as React Flow's testing guide says).
export function mockReactFlowLayout() {
  globalThis.ResizeObserver = class {
    callback: ResizeObserverCallback
    constructor(callback: ResizeObserverCallback) { this.callback = callback }
    observe(target: Element) { this.callback([{ target, contentRect: { width: 1000, height: 640 } } as unknown as ResizeObserverEntry], this as unknown as ResizeObserver) }
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
  globalThis.DOMMatrixReadOnly = class { m22 = 1; constructor(transform?: string) { const scale = transform?.match(/scale\(([0-9.]+)\)/)?.[1]; if (scale) this.m22 = +scale } } as unknown as typeof DOMMatrixReadOnly
  Object.defineProperties(HTMLElement.prototype, {
    offsetHeight: { configurable: true, get() { return parseFloat((this as HTMLElement).style.height) || 64 } },
    offsetWidth: { configurable: true, get() { return parseFloat((this as HTMLElement).style.width) || 184 } },
  })
}
