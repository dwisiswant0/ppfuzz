// Original taken from https://gist.github.com/nikitastupin/b3b64a9f8c0eb74ce37626860193eaec
// Update some based on https://github.com/BlackFan/client-side-prototype-pollution/tree/master/gadgets

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

  if (typeof Vue != 'undefined') {
    gadgets.push('Vue.js');
  }

  if (typeof Demandbase != 'undefined') {
    gadgets.push('Demandbase Tag');
  }

  if (typeof _analytics !== 'undefined' && typeof analyticsGtagManager !== 'undefined') {
    gadgets.push('Google Tag Manager/Analytics');
  }

  if (typeof i18next !== 'undefined') {
    gadgets.push('i18next');
  }

  if (typeof GoogleAnalyticsObject !== 'undefined') {
    gadgets.push('Google Analytics');
  }

  if (typeof Popper !== 'undefined') {
    gadgets.push('Popper.js');
  }

  if (typeof pendo !== 'undefined') {
    gadgets.push('Pendo Agent');
  }

  return gadgets;
})();