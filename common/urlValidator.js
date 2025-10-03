/**
 * URL Validation Utility
 * Prevents SSRF attacks by validating URLs before fetch() calls
 */

/**
 * Validates that a URL is safe to fetch
 * Blocks file://, chrome://, chrome-extension://, and private IP addresses
 * @param {string} urlString - The URL to validate
 * @throws {Error} If URL is invalid or unsafe
 * @returns {URL} Parsed URL object if valid
 */
export function validateUrl(urlString) {
  let url;

  try {
    url = new URL(urlString);
  } catch (e) {
    throw new Error(`Invalid URL: ${urlString}`);
  }

  // Only allow HTTP and HTTPS protocols
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Unsafe URL protocol: ${url.protocol}. Only http: and https: are allowed.`);
  }

  // Block private IP addresses and localhost
  const hostname = url.hostname.toLowerCase();

  // Block localhost variations
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
    throw new Error('Cannot fetch from localhost');
  }

  // Block private IPv4 ranges
  const ipv4Pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const ipv4Match = hostname.match(ipv4Pattern);

  if (ipv4Match) {
    const octets = ipv4Match.slice(1).map(Number);

    // 10.0.0.0/8
    if (octets[0] === 10) {
      throw new Error('Cannot fetch from private IP address (10.x.x.x)');
    }

    // 172.16.0.0/12
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) {
      throw new Error('Cannot fetch from private IP address (172.16-31.x.x)');
    }

    // 192.168.0.0/16
    if (octets[0] === 192 && octets[1] === 168) {
      throw new Error('Cannot fetch from private IP address (192.168.x.x)');
    }

    // 169.254.0.0/16 (link-local)
    if (octets[0] === 169 && octets[1] === 254) {
      throw new Error('Cannot fetch from link-local IP address (169.254.x.x)');
    }
  }

  // Block IPv6 private addresses
  if (hostname.includes(':')) {
    // fc00::/7 (unique local addresses)
    if (hostname.startsWith('fc') || hostname.startsWith('fd')) {
      throw new Error('Cannot fetch from private IPv6 address');
    }
    // fe80::/10 (link-local)
    if (hostname.startsWith('fe80:')) {
      throw new Error('Cannot fetch from link-local IPv6 address');
    }
  }

  return url;
}

/**
 * Safe fetch wrapper that validates URLs before fetching
 * @param {string} urlString - The URL to fetch
 * @param {object} options - Fetch options
 * @returns {Promise<Response>} Fetch response
 */
export async function safeFetch(urlString, options = {}) {
  const url = validateUrl(urlString);
  return fetch(url.href, options);
}
