// Original taken from https://gist.github.com/nikitastupin/b3b64a9f8c0eb74ce37626860193eaec

(() => {
  let gadgets = [];

  if (typeof _satellite !== 'undefined') {
    gadgets.push('Adobe Dynamic Tag Management');
  }

  if (typeof BOOMR !== 'undefined') {
    gadgets.push('Akamai Boomerang');
  }

  if (typeof goog !== 'undefined' && typeof goog.basePath !== 'undefined') {
    gadgets.push('Closure');
  }

  if (typeof DOMPurify !== 'undefined') {
    gadgets.push('DOMPurify');
  }

  if (typeof window.embedly !== 'undefined') {
    gadgets.push('Embedly Cards');
  }

  if (typeof $ !== 'undefined' && typeof $.fn !== 'undefined' && typeof $.fn.jquery !== 'undefined') {
    gadgets.push('jQuery');
  }

  if (typeof filterXSS !== 'undefined') {
    gadgets.push('js-xss');
  }

  if (typeof ko !== 'undefined' && typeof ko.version !== 'undefined') {
    gadgets.push('Knockout.js');
  }

  if (typeof _ !== 'undefined' && typeof _.template !== 'undefined' && typeof _.VERSION !== 'undefined') {
    gadgets.push('Lodash <= 4.17.15');
  }

  if (typeof Marionette !== 'undefined') {
    gadgets.push('Marionette.js / Backbone.js');
  }

  if (typeof recaptcha !== 'undefined') {
    gadgets.push('Google reCAPTCHA');
  }

  if (typeof sanitizeHtml !== 'undefined') {
    gadgets.push('sanitize-html');
  }

  if (typeof analytics !== 'undefined' && typeof analytics.SNIPPET_VERSION !== 'undefined') {
    gadgets.push('Segment Analytics.js');
  }

  if (typeof Sprint !== 'undefined') {
    gadgets.push('Sprint.js');
  }

  if (typeof SwiftypeObject != 'undefined') {
    gadgets.push('Swiftype Site Search (uses jQuery BBQ)');
  }

  if (typeof utag !== 'undefined' && typeof utag.id !== 'undefined') {
    gadgets.push('Tealium Universal Tag');
  }

  if (typeof twq !== 'undefined' && typeof twq.version !== 'undefined') {
    gadgets.push('Twitter Universal Website Tag');
  }

  if (typeof wistiaEmbeds !== 'undefined') {
    gadgets.push('Wistia Embedded Video');
  }

  if (typeof $ !== 'undefined' && typeof $.zepto !== 'undefined') {
    gadgets.push('Zepto.js');
  }

  return gadgets;
})();