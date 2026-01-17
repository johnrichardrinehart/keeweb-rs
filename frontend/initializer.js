// Custom initializer for wasm-bindgen-rayon thread pool
// This runs after WASM is loaded but before the #[wasm_bindgen(start)] function

export default async function initializer(wasm) {
    // Check if SharedArrayBuffer is available (requires COOP/COEP headers)
    if (typeof SharedArrayBuffer === 'undefined') {
        console.warn('SharedArrayBuffer not available - parallel Argon2 will not work');
        console.warn('Make sure the server sends COOP/COEP headers');
        return;
    }

    // Check if the thread pool initializer is exported
    if (typeof wasm.initThreadPool !== 'function') {
        console.warn('initThreadPool not found in WASM exports - parallel Argon2 will not work');
        return;
    }

    // Get the number of logical processors, capped at 12 (max Argon2 parallelism we support)
    const numThreads = Math.min(navigator.hardwareConcurrency || 4, 12);

    console.log(`Initializing rayon thread pool with ${numThreads} threads...`);

    try {
        await wasm.initThreadPool(numThreads);
        console.log(`Rayon thread pool initialized with ${numThreads} threads`);

        // Set a global flag so Rust code knows rayon is ready
        window.__RAYON_POOL_READY__ = true;
    } catch (e) {
        console.error('Failed to initialize rayon thread pool:', e);
        window.__RAYON_POOL_READY__ = false;
    }
}
