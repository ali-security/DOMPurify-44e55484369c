module.exports = function (DOMPurify, window, tests, xssTests) {
  var document = window.document;
  var jQuery = window.jQuery;

  QUnit.cases(tests).test('Sanitization test', function (params, assert) {
    assert.contains(
      DOMPurify.sanitize(params.payload),
      params.expected,
      'Payload: ' + params.payload
    );
  });

  // Config-Flag Tests
  QUnit.test(
    'Config-Flag tests: KEEP_CONTENT + ALLOWED_TAGS / ALLOWED_ATTR',
    function (assert) {
      // KEEP_CONTENT + ALLOWED_TAGS / ALLOWED_ATTR
      assert.equal(
        DOMPurify.sanitize('<iframe>Hello</iframe>', { KEEP_CONTENT: false }),
        ''
      );
      assert.contains(
        DOMPurify.sanitize(
          '<a href="#">abc<b style="color:red">123</b><q class="cite">123</b></a>',
          {
            ALLOWED_TAGS: ['b', 'q'],
            ALLOWED_ATTR: ['style'],
            KEEP_CONTENT: true,
          }
        ),
        [
          'abc<b style="color:red">123</b><q>123</q>',
          'abc<b style="color: red;">123</b><q>123</q>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a href="#">abc<b style="color:red">123</b><q class="cite">123</b></a>',
          {
            ALLOWED_TAGS: ['b', 'q'],
            ALLOWED_ATTR: ['style'],
            KEEP_CONTENT: false,
          }
        ),
        ''
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#">abc</a>', {
          ALLOWED_TAGS: ['b', 'q'],
          KEEP_CONTENT: false,
        }),
        ''
      );
      assert.equal(
        DOMPurify.sanitize('<form><input name="parentNode"></form>', {
          ALLOWED_TAGS: ['input'],
          KEEP_CONTENT: true,
        }),
        '<input>'
      );
    }
  );
  QUnit.test('Config-Flag tests: ALLOW_DATA_ATTR', function (assert) {
    // ALLOW_DATA_ATTR
    assert.equal(
      DOMPurify.sanitize('<a href="#" data-abc"="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      '<a href="#">abc</a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" data-abc="foo">abc</a>', {
        ALLOW_DATA_ATTR: false,
      }),
      '<a href="#">abc</a>'
    );
    assert.contains(
      DOMPurify.sanitize('<a href="#" data-abc="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      [
        '<a data-abc="foo" href="#">abc</a>',
        '<a href="#" data-abc="foo">abc</a>',
      ]
    );
    assert.contains(
      DOMPurify.sanitize('<a href="#" data-abc-1-2-3="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      [
        '<a data-abc-1-2-3="foo" href="#">abc</a>',
        '<a href="#" data-abc-1-2-3="foo">abc</a>',
      ]
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" data-""="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      '<a href="#">abc</a>'
    );
    assert.contains(
      DOMPurify.sanitize('<a href="#" data-äöü="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      [
        '<a href="#" data-äöü="foo">abc</a>',
        '<a data-äöü="foo" href="#">abc</a>',
      ]
    );
    assert.contains(
      DOMPurify.sanitize('<a href="#" data-\u00B7._="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      [
        '<a data-\u00B7._="foo" href="#">abc</a>',
        '<a href="#">abc</a>',
        '<a href="#" data-·._="foo">abc</a>',
      ] // IE11 and Edge throw an InvalidCharacterError
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" data-\u00B5="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      '<a href="#">abc</a>'
    );
  });
  QUnit.test('Config-Flag tests: ADD_TAGS', function (assert) {
    // ADD_TAGS
    assert.equal(
      DOMPurify.sanitize('<my-component>abc</my-component>', {
        ADD_TAGS: ['my-component'],
      }),
      '<my-component>abc</my-component>'
    );
    assert.equal(
      DOMPurify.sanitize('<my-ĸompønent>abc</my-ĸompønent>', {
        ADD_TAGS: ['my-ĸompønent'],
      }),
      '<my-ĸompønent>abc</my-ĸompønent>'
    );
  });
  QUnit.test('Config-Flag tests: ADD_TAGS + ADD_ATTR', function (assert) {
    // ADD_TAGS + ADD_ATTR
    assert.equal(
      DOMPurify.sanitize('<my-component my-attr="foo">abc</my-component>', {
        ADD_TAGS: ['my-component'],
      }),
      '<my-component>abc</my-component>'
    );
    assert.equal(
      DOMPurify.sanitize('<my-component my-attr="foo">abc</my-component>', {
        ADD_TAGS: ['my-component'],
        ADD_ATTR: ['my-attr'],
      }),
      '<my-component my-attr="foo">abc</my-component>'
    );
    assert.equal(
      DOMPurify.sanitize('<my-ĸompønent my-æŧŧr="foo">abc</my-ĸompønent>', {
        ADD_TAGS: ['my-ĸompønent'],
      }),
      '<my-ĸompønent>abc</my-ĸompønent>'
    );
    assert.equal(
      DOMPurify.sanitize('<my-ĸompønent my-æŧŧr="foo">abc</my-ĸompønent>', {
        ADD_TAGS: ['my-ĸompønent'],
        ADD_ATTR: ['my-æŧŧr'],
      }),
      '<my-ĸompønent my-æŧŧr="foo">abc</my-ĸompønent>'
    );
  });
  QUnit.test('Config-Flag tests: SAFE_FOR_JQUERY', function (assert) {
    //SAFE_FOR_JQUERY
    assert.equal(
      DOMPurify.sanitize(
        '<a>123</a><option><style><img src=x onerror=alert(1)>',
        { SAFE_FOR_JQUERY: false }
      ),
      '<a>123</a><option><style><img src=x onerror=alert(1)></style></option>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123</a><option><style><img src=x onerror=alert(1)>',
        { SAFE_FOR_JQUERY: true }
      ),
      '<a>123</a><option><style>&lt;img src=x onerror=alert(1)></style></option>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<option><style></option></select><b><img src=xx: onerror=alert(1)></style></option>',
        { SAFE_FOR_JQUERY: false }
      ),
      '<option><style></option></select><b><img src=xx: onerror=alert(1)></style></option>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<option><style></option></select><b><img src=xx: onerror=alert(1)></style></option>',
        { SAFE_FOR_JQUERY: true }
      ),
      '<option><style>&lt;/option>&lt;/select>&lt;b>&lt;img src=xx: onerror=alert(1)></style></option>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<option><iframe></select><b><script>alert(1)</script>',
        { SAFE_FOR_JQUERY: false, KEEP_CONTENT: false }
      ),
      '<option></option>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<option><iframe></select><b><script>alert(1)</script>',
        { SAFE_FOR_JQUERY: true, KEEP_CONTENT: false }
      ),
      '<option></option>'
    );
    assert.equal(
      DOMPurify.sanitize('<b><style><style/><img src=xx: onerror=alert(1)>', {
        SAFE_FOR_JQUERY: false,
      }),
      '<b><style><style/><img src=xx: onerror=alert(1)></style></b>'
    );
    assert.equal(
      DOMPurify.sanitize('<b><style><style/><img src=xx: onerror=alert(1)>', {
        SAFE_FOR_JQUERY: true,
      }),
      '<b><style>&lt;style/>&lt;img src=xx: onerror=alert(1)></style></b>'
    );
    assert.contains(
      DOMPurify.sanitize('1<template><s>000</s></template>2', {
        SAFE_FOR_JQUERY: true,
      }),
      ['1<template><s>000</s></template>2', '1<template></template>2']
    );
    assert.contains(
      DOMPurify.sanitize('<template><s>000</s></template>', {
        SAFE_FOR_JQUERY: true,
      }),
      ['', '<template><s>000</s></template>']
    );
    // see https://github.com/cure53/DOMPurify/issues/283
    assert.equal(
      DOMPurify.sanitize('<i>&amp;amp; &lt;</i>', { SAFE_FOR_JQUERY: true }),
      '<i>&amp;amp; &lt;</i>'
    );
  });
  QUnit.test('Config-Flag tests: SAFE_FOR_TEMPLATES', function (assert) {
    //SAFE_FOR_TEMPLATES
    assert.equal(
      DOMPurify.sanitize(
        '<a>123{{456}}<b><style><% alert(1) %></style>456</b></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a> <b><style> </style>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a data-bind="style: alert(1)"></a>', {
        SAFE_FOR_TEMPLATES: true,
      }),
      '<a></a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a data-harmless=""></a>', {
        SAFE_FOR_TEMPLATES: true,
        ALLOW_DATA_ATTR: true,
      }),
      '<a></a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a data-harmless=""></a>', {
        SAFE_FOR_TEMPLATES: false,
        ALLOW_DATA_ATTR: false,
      }),
      '<a></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>{{123}}{{456}}<b><style><% alert(1) %><% 123 %></style>456</b></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a> <b><style> </style>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>{{123}}abc{{456}}<b><style><% alert(1) %>def<% 123 %></style>456</b></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a> <b><style> </style>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123{{45{{6}}<b><style><% alert(1)%> %></style>456</b></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a> <b><style> </style>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123{{45}}6}}<b><style><% <%alert(1) %></style>456</b></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a> <b><style> </style>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123{{<b>456}}</b><style><% alert(1) %></style>456</a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a>123 <b> </b><style> </style>456</a>'
    );
    assert.contains(
      DOMPurify.sanitize(
        '<b>{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}</b>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      ['<b>  </b>', '<b> </b>', '<b> <form><img src="x"></form> </b>']
    );
    assert.contains(
      DOMPurify.sanitize(
        '<b>he{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}ya</b>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      ['<b>he  ya</b>', '<b>he </b>', '<b>he <form><img src="x"></form> ya</b>']
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123<% <b>456}}</b><style>{{ alert(1) }}</style>456 %></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a>123 <b> </b><style> </style> </a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a href="}}javascript:alert(1)"></a>', {
        SAFE_FOR_TEMPLATES: true,
      }),
      '<a></a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a class="{{999-333}}"></a>', {
        SAFE_FOR_TEMPLATES: true,
      }),
      '<a class=" "></a>'
    );
    assert.equal(
      DOMPurify.sanitize('{{999-333}}', { SAFE_FOR_TEMPLATES: true }),
      ' '
    );
    assert.equal(
      DOMPurify.sanitize('{<x>{333+333}<x>}', { SAFE_FOR_TEMPLATES: true }),
      ' '
    );
  });
  QUnit.test('Config-Flag tests: SANITIZE_DOM', function (assert) {
    // SANITIZE_DOM
    assert.equal(
      DOMPurify.sanitize('<img src="x" name="implementation">', {
        SANITIZE_DOM: true,
      }),
      '<img src="x">'
    );
    assert.equal(
      DOMPurify.sanitize('<img src="x" name="createNodeIterator">', {
        SANITIZE_DOM: true,
      }),
      '<img src="x">'
    );
    assert.equal(
      DOMPurify.sanitize('<img src="x" name="getElementById">', {
        SANITIZE_DOM: false,
      }),
      '<img name="getElementById" src="x">'
    );
    assert.equal(
      DOMPurify.sanitize('<img src="x" name="getElementById">', {
        SANITIZE_DOM: true,
      }),
      '<img src="x">'
    );
    assert.equal(
      DOMPurify.sanitize('<a href="x" id="location">click</a>', {
        SANITIZE_DOM: true,
      }),
      '<a href="x">click</a>'
    );
    assert.contains(
      DOMPurify.sanitize('<form><input name="attributes"></form>', {
        ADD_TAGS: ['form'],
        SANITIZE_DOM: false,
      }),
      ['', '<form><input name="attributes"></form>']
    );
    assert.contains(
      DOMPurify.sanitize('<form><input name="attributes"></form>', {
        ADD_TAGS: ['form'],
        SANITIZE_DOM: true,
      }),
      ['', '<form><input name="attributes"></form>', '<form><input></form>']
    );
  });
  QUnit.test('Config-Flag tests: WHOLE_DOCUMENT', function (assert) {
    //WHOLE_DOCUMENT
    assert.equal(DOMPurify.sanitize('123', { WHOLE_DOCUMENT: false }), '123');
    assert.equal(
      DOMPurify.sanitize('123', { WHOLE_DOCUMENT: true }),
      '<html><head></head><body>123</body></html>'
    );
    assert.equal(
      DOMPurify.sanitize('<style>*{color:red}</style>', {
        WHOLE_DOCUMENT: false,
      }),
      ''
    );
    assert.equal(
      DOMPurify.sanitize('<style>*{color:red}</style>', {
        WHOLE_DOCUMENT: true,
      }),
      '<html><head><style>*{color:red}</style></head><body></body></html>'
    );
    assert.equal(
      DOMPurify.sanitize('123<style>*{color:red}</style>', {
        WHOLE_DOCUMENT: false,
      }),
      '123<style>*{color:red}</style>'
    );
    assert.equal(
      DOMPurify.sanitize('123<style>*{color:red}</style>', {
        WHOLE_DOCUMENT: true,
      }),
      '<html><head></head><body>123<style>*{color:red}</style></body></html>'
    );
  });
  QUnit.test('Config-Flag tests: RETURN_DOM', function (assert) {
    //RETURN_DOM
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456</b></a>', { RETURN_DOM: true })
        .outerHTML,
      '<body><a>123<b>456</b></a></body>'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>', {
        RETURN_DOM: true,
      }).outerHTML,
      '<body><a>123<b>456</b></a></body>'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456</b></a>', {
        RETURN_DOM: true,
        WHOLE_DOCUMENT: true,
      }).outerHTML,
      '<html><head></head><body><a>123<b>456</b></a></body></html>'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>', {
        RETURN_DOM: true,
        WHOLE_DOCUMENT: true,
      }).outerHTML,
      '<html><head></head><body><a>123<b>456</b></a></body></html>'
    );
    assert.equal(
      DOMPurify.sanitize('123', { RETURN_DOM: true }).outerHTML,
      '<body>123</body>'
    );
  });
  QUnit.test('Config-Flag tests: RETURN_DOM_IMPORT', function (assert) {
    //RETURN_DOM_IMPORT
    assert.notEqual(
      DOMPurify.sanitize('123', { RETURN_DOM: true }).ownerDocument,
      document
    );
    assert.notEqual(
      DOMPurify.sanitize('123', { RETURN_DOM: true, RETURN_DOM_IMPORT: false })
        .ownerDocument,
      document
    );
    assert.equal(
      DOMPurify.sanitize('123', { RETURN_DOM: true, RETURN_DOM_IMPORT: true })
        .ownerDocument,
      document
    );
    assert.notEqual(
      DOMPurify.sanitize('123', { RETURN_DOM_FRAGMENT: true }).ownerDocument,
      document
    );
    assert.notEqual(
      DOMPurify.sanitize('123', {
        RETURN_DOM_FRAGMENT: true,
        RETURN_DOM_IMPORT: false,
      }).ownerDocument,
      document
    );
    assert.equal(
      DOMPurify.sanitize('123', {
        RETURN_DOM_FRAGMENT: true,
        RETURN_DOM_IMPORT: true,
      }).ownerDocument,
      document
    );
  });
  QUnit.test('Config-Flag tests: RETURN_DOM_FRAGMENT', function (assert) {
    //RETURN_DOM_FRAGMENT
    // attempt clobbering
    var fragment = DOMPurify.sanitize('foo<img id="createDocumentFragment">', {
      RETURN_DOM_FRAGMENT: true,
    });
    assert.equal(fragment.nodeType, 11);
    assert.notEqual(fragment.ownerDocument, document);
    assert.equal(fragment.firstChild && fragment.firstChild.nodeValue, 'foo');
    // again, but without SANITIZE_DOM
    fragment = DOMPurify.sanitize('foo<img id="createDocumentFragment">', {
      RETURN_DOM_FRAGMENT: true,
      SANITIZE_DOM: false,
    });
    assert.equal(fragment.nodeType, 11);
    assert.notEqual(fragment.ownerDocument, document);
    assert.equal(fragment.firstChild && fragment.firstChild.nodeValue, 'foo');
  });
  QUnit.test('Config-Flag tests: IN_PLACE', function (assert) {
    //IN_PLACE
    var dirty = document.createElement('a');
    dirty.setAttribute('href', 'javascript:alert(1)');
    var clean = DOMPurify.sanitize(dirty, { IN_PLACE: true });
    assert.equal(dirty, clean); // should return the input node
    assert.equal(dirty.href, ''); // should still sanitize
  });
  QUnit.test(
    'Config-Flag tests: SAFE_FOR_TEMPLATES strips boundary-spanning Mustache expressions in IN_PLACE mode',
    function (assert) {
      // Regression for the IN_PLACE counterpart of CVE-2026-41239.
      // Per-text-node scrubbing alone misses {{...}} whose halves sit on
      // either side of a stripped foreign element: each text node holds only
      // a single '{' or '}', so MUSTACHE_EXPR (which requires '{{' or '}}')
      // matches nothing. After sanitization removes the foreign element the
      // surrounding text fragments are adjacent, and the serialized
      // innerHTML — which is what a template-evaluating framework reads —
      // shows '{{...}}' as a single interpolatable expression.
      var dirty = document.createElement('div');
      dirty.innerHTML =
        '{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}';
      DOMPurify.sanitize(dirty, {
        SAFE_FOR_TEMPLATES: true,
        IN_PLACE: true,
      });
      assert.notOk(
        /\{\{[\s\S]*\}\}/.test(dirty.innerHTML),
        'merged Mustache expression should be scrubbed'
      );
      assert.notOk(
        /constructor/.test(dirty.innerHTML),
        'expression body should not survive scrubbing'
      );
    }
  );
  QUnit.test(
    'Config-Flag tests: SAFE_FOR_TEMPLATES strips boundary-spanning Mustache expressions in IN_PLACE mode on a DocumentFragment',
    function (assert) {
      // Same bug class as above, for an in-place root that has no innerHTML
      // of its own: the merged text nodes must still be scrubbed.
      var dirty = document.createDocumentFragment();
      var wrapper = document.createElement('div');
      wrapper.innerHTML =
        '{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}';
      dirty.appendChild(wrapper);
      var clean = DOMPurify.sanitize(dirty, {
        SAFE_FOR_TEMPLATES: true,
        IN_PLACE: true,
      });
      assert.equal(dirty, clean, 'should return the input node');
      var container = document.createElement('div');
      container.appendChild(dirty);
      assert.notOk(
        /\{\{[\s\S]*\}\}/.test(container.innerHTML),
        'merged Mustache expression should be scrubbed'
      );
      assert.notOk(
        /constructor/.test(container.innerHTML),
        'expression body should not survive scrubbing'
      );
      // Expression halves sitting directly on the fragment root
      var source = document.createElement('div');
      source.innerHTML =
        '{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}';
      dirty = document.createDocumentFragment();
      while (source.firstChild) {
        dirty.appendChild(source.firstChild);
      }

      clean = DOMPurify.sanitize(dirty, {
        SAFE_FOR_TEMPLATES: true,
        IN_PLACE: true,
      });
      assert.equal(dirty, clean, 'should return the input node');
      container = document.createElement('div');
      container.appendChild(dirty);
      assert.notOk(
        /\{\{[\s\S]*\}\}/.test(container.innerHTML),
        'merged Mustache expression should be scrubbed on the fragment root'
      );
      assert.notOk(
        /constructor/.test(container.innerHTML),
        'expression body should not survive scrubbing on the fragment root'
      );
    }
  );
  QUnit.test(
    'Config-Flag tests: SAFE_FOR_TEMPLATES pins RETURN_DOM_FRAGMENT scrub behavior',
    function (assert) {
      // RETURN_DOM_FRAGMENT was fixed alongside RETURN_DOM in CVE-2026-41239
      // (both reach the body.innerHTML scrub). Pinning the fragment path
      // here so future refactors of the post-walk return logic do not
      // silently regress it.
      var result = DOMPurify.sanitize(
        '<div>{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}</div>',
        {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM_FRAGMENT: true,
        }
      );
      var container = document.createElement('div');
      container.appendChild(result);
      assert.notOk(
        /\{\{[\s\S]*\}\}/.test(container.innerHTML),
        'merged Mustache expression should be scrubbed in fragment mode'
      );
    }
  );
  QUnit.test(
    'Config-Flag tests: SAFE_FOR_TEMPLATES with RETURN_DOM',
    function (assert) {
      // CVE-2026-41239: the expression halves only merge once the foreign
      // elements are stripped, so the returned body must be scrubbed too.
      var returnNode = DOMPurify.sanitize(
        '{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}',
        {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        }
      );
      assert.notOk(
        /\{\{[\s\S]*\}\}/.test(returnNode.innerHTML),
        'merged Mustache expression should be scrubbed in RETURN_DOM mode'
      );
      assert.notOk(
        /constructor/.test(returnNode.innerHTML),
        'expression body should not survive scrubbing'
      );
      // Same payload passed in as a DOM node
      var dirty = document.createElement('div');
      dirty.innerHTML =
        '{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}';
      returnNode = DOMPurify.sanitize(dirty, {
        SAFE_FOR_TEMPLATES: true,
        RETURN_DOM: true,
      });
      assert.notOk(
        /\{\{[\s\S]*\}\}/.test(returnNode.innerHTML),
        'merged Mustache expression should be scrubbed for DOM node input'
      );
      assert.notOk(
        /constructor/.test(returnNode.innerHTML),
        'expression body should not survive scrubbing for DOM node input'
      );
      // Same payload with the returned node imported into the document
      returnNode = DOMPurify.sanitize(
        '{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}',
        {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
          RETURN_DOM_IMPORT: true,
        }
      );
      assert.notOk(
        /\{\{[\s\S]*\}\}/.test(returnNode.innerHTML),
        'merged Mustache expression should be scrubbed with RETURN_DOM_IMPORT'
      );
      // Markup without template expressions is left intact
      returnNode = DOMPurify.sanitize('<a>123</a><b>456</b>', {
        SAFE_FOR_TEMPLATES: true,
        RETURN_DOM: true,
      });
      assert.equal(returnNode.innerHTML, '<a>123</a><b>456</b>');
    }
  );
  QUnit.test('Config-Flag tests: FORBID_TAGS', function (assert) {
    //FORBID_TAGS
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456</b></a>', { FORBID_TAGS: ['b'] }),
      '<a>123456</a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>789', {
        FORBID_TAGS: ['a', 'b'],
      }),
      '123456789'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456</b></a>', { FORBID_TAGS: ['c'] }),
      '<a>123<b>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>789', {
        FORBID_TAGS: ['script', 'b'],
      }),
      '<a>123456</a>789'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456</b></a>', {
        ADD_TAGS: ['b'],
        FORBID_TAGS: ['b'],
      }),
      '<a>123456</a>'
    );
  });
  QUnit.test('Config-Flag tests: FORBID_ATTR', function (assert) {
    //FORBID_ATTR
    assert.equal(
      DOMPurify.sanitize('<a x="1">123<b>456</b></a>', { FORBID_ATTR: ['x'] }),
      '<a>123<b>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a class="0" x="1">123<b y="1">456<script>alert(1)</script></b></a>789',
        { FORBID_ATTR: ['x', 'y'] }
      ),
      '<a class="0">123<b>456</b></a>789'
    );
    assert.equal(
      DOMPurify.sanitize('<a y="1">123<b y="1" y="2">456</b></a>', {
        FORBID_ATTR: ['y'],
      }),
      '<a>123<b>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123<b x="1">456<script y="1">alert(1)</script></b></a>789',
        { FORBID_ATTR: ['x', 'y'] }
      ),
      '<a>123<b>456</b></a>789'
    );
  });
  QUnit.test('Test dirty being an array', function (assert) {
    assert.equal(
      DOMPurify.sanitize(['<a>123<b>456</b></a>']),
      '<a>123<b>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(['<img src=', 'x onerror=alert(1)>']),
      '<img src=",x">'
    );
  });
  // XSS tests: Native DOM methods (alert() should not be called)
  QUnit.cases(xssTests).asyncTest('XSS test: native', function (
    params,
    assert
  ) {
    document.getElementById('qunit-fixture').innerHTML = DOMPurify.sanitize(
      params.payload
    );
    setTimeout(function () {
      QUnit.start();
      assert.notEqual(window.xssed, true, 'alert() was called');
      // Teardown
      document.getElementById('qunit-fixture').innerHTML = '';
      window.xssed = false;
    }, 100);
  });
  // XSS tests: jQuery (alert() should not be called)
  QUnit.cases(xssTests).asyncTest('XSS test: jQuery', function (
    params,
    assert
  ) {
    jQuery('#qunit-fixture').html(
      DOMPurify.sanitize(params.payload, { SAFE_FOR_JQUERY: true })
    );
    setTimeout(function () {
      QUnit.start();
      assert.notEqual(window.xssed, true, 'alert() was called');
      // Teardown
      jQuery('#qunit-fixture').empty();
      window.xssed = false;
    }, 100);
  });
  // document.write tests to handle FF's strange behavior
  QUnit.cases(xssTests).asyncTest(
    'XSS test: document.write() into iframe',
    function (params, assert) {
      var iframe = document.createElement('iframe');
      iframe.src = 'about:blank';
      iframe.onload = function () {
        QUnit.start();
        iframe.contentDocument.write(
          '<script>window.alert=function(){top.xssed=true;}</script>' +
            DOMPurify.sanitize(params.payload)
        );
        assert.notEqual(
          window.xssed,
          true,
          'alert() was called from document.write()'
        );
        window.xssed = false;
        iframe.parentNode.removeChild(iframe);
      };
      document.body.appendChild(iframe);
    }
  );
  // cross-check that document.write into iframe works properly
  QUnit.asyncTest('XSS test: document.write() into iframe', function (assert) {
    window.xssed = false;
    var iframe = document.createElement('iframe');
    iframe.src = 'about:blank';
    iframe.onload = function () {
      QUnit.start();
      iframe.contentDocument.write(
        '<script>window.alert=function(){parent.xssed=true;}</script><script>alert(1);</script>'
      );
      assert.equal(window.xssed, true, 'alert() was called but not detected');
      window.xssed = false;
      iframe.parentNode.removeChild(iframe);
    };
    document.body.appendChild(iframe);
  });
  // Check for isSupported property
  QUnit.test('DOMPurify property tests', function (assert) {
    assert.equal(typeof DOMPurify.isSupported, 'boolean');
  });
  // Test with a custom window object
  QUnit.test('DOMPurify custom window tests', function (assert) {
    assert.strictEqual(typeof DOMPurify(null).version, 'string');
    assert.strictEqual(DOMPurify(null).isSupported, false);
    assert.strictEqual(DOMPurify(null).sanitize, undefined);
    assert.strictEqual(typeof DOMPurify({}).version, 'string');
    assert.strictEqual(DOMPurify({}).isSupported, false);
    assert.strictEqual(DOMPurify({}).sanitize, undefined);
    assert.strictEqual(
      typeof DOMPurify({ document: 'not really a document' }).version,
      'string'
    );
    assert.strictEqual(
      DOMPurify({ document: 'not really a document' }).isSupported,
      false
    );
    assert.strictEqual(
      DOMPurify({ document: 'not really a document' }).sanitize,
      undefined
    );
    assert.strictEqual(typeof DOMPurify(window).version, 'string');
    assert.strictEqual(typeof DOMPurify(window).sanitize, 'function');
  });
  // Test to prevent security issues with pre-clobbered DOM
  QUnit.test(
    'sanitize() should not throw if the original document is clobbered _after_ DOMPurify has been instantiated',
    function (assert) {
      var evilNode = document.createElement('div');
      evilNode.innerHTML =
        '<img id="implementation"><img id="createNodeIterator"><img id="importNode"><img id="createElement">';
      document.body.appendChild(evilNode);
      try {
        // tests implementation and createNodeIterator
        var resultPlain = DOMPurify.sanitize('123');
        // tests importNode
        var resultImport = DOMPurify.sanitize('123', {
          RETURN_DOM: true,
          RETURN_DOM_IMPORT: true,
        });
        // tests createElement
        var resultBody = DOMPurify.sanitize('123<img id="body">');
      } finally {
        // clean up before doing the actual assertions, otherwise qunit/jquery/etc might blow up
        document.body.removeChild(evilNode);
      }
      assert.equal(resultPlain, '123');
      assert.equal(resultImport.ownerDocument, document);
      assert.equal(resultBody, '123<img>');
    }
  );
  // Test to check against a hang in MSIE (#89)
  QUnit.test(
    'sanitize() should not hang on MSIE when hook changes textContent',
    function (assert) {
      DOMPurify.addHook('afterSanitizeElements', function (node) {
        if (node.nodeType && node.nodeType === document.TEXT_NODE) {
          node.textContent = 'foo';
        }
        return node;
      });
      var dirty =
        '<div><p>This is a beatufiul text</p><p>This is too</p></div>';
      var modified = '<div><p>foo</p><p>foo</p></div>';
      assert.equal(DOMPurify.sanitize(dirty), modified);
      DOMPurify.removeHooks('afterSanitizeElements');
    }
  );
  // Tests to ensure that a configuration can be set and cleared
  QUnit.test(
    'ensure that a persistent configuration can be set and cleared',
    function (assert) {
      var dirty = '<my-component>abc</my-component>';
      assert.equal(DOMPurify.sanitize(dirty), 'abc');
      DOMPurify.setConfig({ ADD_TAGS: ['my-component'] });
      assert.equal(
        DOMPurify.sanitize(dirty),
        '<my-component>abc</my-component>'
      );
      DOMPurify.clearConfig();
      assert.equal(DOMPurify.sanitize(dirty), 'abc');
    }
  );
  // Test to ensure that a hook can add allowed tags / attributes on the fly
  QUnit.test(
    'ensure that a hook can add allowed tags / attributes on the fly',
    function (assert) {
      DOMPurify.addHook('uponSanitizeElement', function (node, data) {
        if (
          node.nodeName &&
          node.nodeName.match(/^\w+-\w+$/) &&
          !data.allowedTags[data.tagName]
        ) {
          data.allowedTags[data.tagName] = true;
        }
      });
      DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
        if (
          data.attrName &&
          data.attrName.match(/^\w+-\w+$/) &&
          !data.allowedAttributes[data.attrName]
        ) {
          data.allowedAttributes[data.attrName] = true;
        }
      });
      var dirty =
        '<p>HE<iframe></iframe><is-custom onload="alert(1)" super-custom="test" />LLO</p>';
      var modified = '<p>HE<is-custom super-custom="test">LLO</is-custom></p>';
      assert.equal(DOMPurify.sanitize(dirty), modified);
      DOMPurify.removeHooks('uponSanitizeElement');
      DOMPurify.removeHooks('uponSanitizeAttribute');
    }
  );
  // Test to ensure that if input[type=file] is badlisted and flagged as an
  // attribute not to keep via hookEvent.keepAttr, it should be removed despite
  // it being an issue of being able to programmatically add it back in Safari.
  QUnit.test(
    'ensure that input[type=file] is removed via hookEvent keepAttr',
    function (assert) {
      DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
        if (
          node.nodeName == 'INPUT' &&
          node.getAttribute('type') &&
          node.getAttribute('type') == 'file'
        ) {
          data.keepAttr = false;
        }
      });
      var dirty = '<input type="file" />';
      var modified = '<input>';
      if (window.name == 'nodejs') {
        assert.equal(DOMPurify.sanitize(dirty), modified);
      } else {
        assert.expect(0);
      }
      DOMPurify.removeHooks('uponSanitizeAttribute');
    }
  );

  // -------------------------------------------------------------------
  // Persistent-config path (setConfig). sanitize() skips _parseConfig once
  // setConfig() has run, so the sets are not re-derived per call: a hook
  // write to data.allowedTags / data.allowedAttributes used to mutate the
  // allowlist for the instance lifetime, across calls and elements. The
  // sets are restored and cloned on every sanitize() call on this path.
  // (GHSA-cmwh-pvxp-8882)
  // -------------------------------------------------------------------

  QUnit.test(
    'GHSA-cmwh-pvxp-8882: setConfig: attribute hook does not poison later calls',
    function (assert) {
      DOMPurify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
      DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
        if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
          data.allowedAttributes['onerror'] = true;
        }
      });

      try {
        // A trusted element widens onerror for its own call.
        assert.ok(
          DOMPurify.sanitize(
            '<img data-trusted="1" src="x" onerror="ok()">'
          ).indexOf('onerror') !== -1,
          'in-call widening works for the trusted element under setConfig'
        );

        // A later untrusted call must NOT inherit the widened attribute.
        assert.equal(
          DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
          '<img src="x">',
          'untrusted call after trusted render strips onerror'
        );

        // Repeated calls must stay clean (no accumulated clone state).
        for (var i = 0; i < 5; i++) {
          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(' + i + ')">'),
            '<img src="x">',
            'repeated untrusted call ' + i + ' stays clean'
          );
        }
      } finally {
        DOMPurify.removeHooks('uponSanitizeAttribute');
        DOMPurify.clearConfig();
      }
    }
  );

  QUnit.test(
    'GHSA-cmwh-pvxp-8882: setConfig: element hook does not poison later calls',
    function (assert) {
      DOMPurify.setConfig({ ALLOWED_TAGS: ['span'], ALLOWED_ATTR: [] });
      DOMPurify.addHook('uponSanitizeElement', function (node, data) {
        if (
          node.getAttribute &&
          node.getAttribute('data-trusted') === '1' &&
          data.allowedTags
        ) {
          data.allowedTags['img'] = true;
        }
      });

      try {
        DOMPurify.sanitize('<span data-trusted="1"><img src="x"></span>');

        assert.equal(
          DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
          '',
          'untrusted <img> not allowed after trusted render under setConfig'
        );
      } finally {
        DOMPurify.removeHooks('uponSanitizeElement');
        DOMPurify.clearConfig();
      }
    }
  );

  QUnit.test(
    'GHSA-cmwh-pvxp-8882: setConfig: clearConfig restores a clean state',
    function (assert) {
      DOMPurify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
      DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
        if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
          data.allowedAttributes['onerror'] = true;
        }
      });

      try {
        DOMPurify.sanitize('<img data-trusted="1" src="x" onerror="ok()">');

        DOMPurify.clearConfig();

        assert.equal(
          DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
          '<img src="x">',
          'default-cfg call after clearConfig strips onerror'
        );
      } finally {
        DOMPurify.removeHooks('uponSanitizeAttribute');
        DOMPurify.clearConfig();
      }
    }
  );

  QUnit.test(
    'GHSA-cmwh-pvxp-8882: setConfig: hook widening does not survive hook removal',
    function (assert) {
      DOMPurify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
      DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
        if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
          data.allowedAttributes['onerror'] = true;
        }
      });

      try {
        DOMPurify.sanitize('<img data-trusted="1" src="x" onerror="ok()">');

        // Removing the hook must not leave the widened allowlist behind.
        DOMPurify.removeHooks('uponSanitizeAttribute');

        assert.equal(
          DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
          '<img src="x">',
          'untrusted call after the hook is removed strips onerror'
        );
      } finally {
        DOMPurify.removeHooks('uponSanitizeAttribute');
        DOMPurify.clearConfig();
      }
    }
  );

  /* CVE-2026-65902: hook-driven allowlist pollution. The data.allowedTags /
     data.allowedAttributes fields handed to uponSanitizeElement /
     uponSanitizeAttribute hooks are references to the live ALLOWED_TAGS /
     ALLOWED_ATTR sets, which are the module-level defaults when no explicit
     ALLOWED_TAGS / ALLOWED_ATTR is configured. A hook writing
     data.allowedTags.script = true must not widen the defaults of later
     calls, even after removeAllHooks() and clearConfig(). The sets are
     cloned per sanitize() call whenever such a hook is registered, so the
     documented in-call widening keeps working. Each test uses a fresh
     instance, as the bug under test is cross-call pollution. */
  var withFreshPurify = function (callback) {
    var purify = DOMPurify(window);
    try {
      callback(purify);
    } finally {
      purify.removeAllHooks();
      purify.clearConfig();
    }
  };
  QUnit.test(
    'CVE-2026-65902: baseline, <script> and onclick are stripped under default config',
    function (assert) {
      withFreshPurify(function (purify) {
        assert.equal(
          purify.sanitize('<svg><script>alert(1)</script></svg>'),
          '<svg></svg>',
          'fresh default sanitize strips <script>'
        );
        assert.equal(
          purify.sanitize('<a onclick="alert(1)">x</a>'),
          '<a>x</a>',
          'fresh default sanitize strips onclick'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: in-call widening via hook still works',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node, data) {
          if (data.tagName === 'is-custom') {
            data.allowedTags['is-custom'] = true;
          }
        });
        purify.addHook('uponSanitizeAttribute', function (node, data) {
          if (data.attrName === 'super-custom') {
            data.allowedAttributes['super-custom'] = true;
          }
        });

        var input = '<p>HE<is-custom super-custom="test">LLO</is-custom></p>';
        assert.equal(
          purify.sanitize(input),
          input,
          'guarded hook widens allowlist for matching element in-call'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: unguarded element hook does not poison subsequent default-config calls',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node, data) {
          // The leaky pattern: unconditionally widen
          data.allowedTags.script = true;
        });

        assert.equal(
          purify.sanitize('<svg><script>1</script></svg>'),
          '<svg><script>1</script></svg>',
          'in-call widening still works while hook is registered'
        );

        purify.removeAllHooks();
        purify.clearConfig();

        assert.equal(
          purify.sanitize('<svg><script>alert(1)</script></svg>'),
          '<svg></svg>',
          'default sanitize after element-hook removal strips <script>'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: unguarded attribute hook does not poison subsequent default-config calls',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeAttribute', function (node, data) {
          data.allowedAttributes.onclick = true;
        });

        assert.ok(
          purify.sanitize('<a onclick="alert(1)">x</a>').indexOf('onclick') !==
            -1,
          'in-call widening still works for attribute hook'
        );

        purify.removeAllHooks();
        purify.clearConfig();

        assert.equal(
          purify.sanitize('<a onclick="alert(1)">x</a>'),
          '<a>x</a>',
          'default sanitize after attr-hook removal strips onclick'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: pollution does not cross instance boundaries',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node, data) {
          data.allowedTags.script = true;
        });
        purify.sanitize('<svg><script>alert(1)</script></svg>');

        var freshInstance = DOMPurify(window);
        assert.equal(
          freshInstance.sanitize('<svg><script>alert(1)</script></svg>'),
          '<svg></svg>',
          'fresh DOMPurify instance must not inherit poisoned defaults'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: read-only hook does not poison defaults',
    function (assert) {
      withFreshPurify(function (purify) {
        var sawScriptKey;
        purify.addHook('uponSanitizeElement', function (node, data) {
          if (sawScriptKey === undefined) {
            sawScriptKey = 'script' in data.allowedTags;
          }
        });

        purify.sanitize('<div><span>hi</span></div>');

        assert.strictEqual(
          sawScriptKey,
          false,
          'hook sees default allowlist with script NOT included'
        );

        purify.removeAllHooks();
        purify.clearConfig();

        assert.equal(
          purify.sanitize('<svg><script>alert(1)</script></svg>'),
          '<svg></svg>',
          'read-only hook does not poison defaults'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: multiple polluting calls do not accumulate state in defaults',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node, data) {
          data.allowedTags.script = true;
          data.allowedTags.iframe = true;
          data.allowedTags.object = true;
        });

        for (var i = 0; i < 10; i++) {
          purify.sanitize('<div></div>');
        }

        purify.removeAllHooks();
        purify.clearConfig();

        assert.equal(
          purify.sanitize('<svg><script>1</script></svg>'),
          '<svg></svg>',
          'script still stripped after 10 polluting calls'
        );
        assert.equal(
          purify.sanitize('<iframe src="x"></iframe>'),
          '',
          'iframe still stripped after 10 polluting calls'
        );
        assert.equal(
          purify.sanitize('<object data="x"></object>'),
          '',
          'object still stripped after 10 polluting calls'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: explicit cfg.ALLOWED_TAGS path is unaffected by hook mutation in other calls',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node, data) {
          data.allowedTags.script = true;
        });

        var withCfg = purify.sanitize('<svg><script>alert(1)</script></svg>', {
          ALLOWED_TAGS: ['svg'],
        });
        assert.ok(
          withCfg.indexOf('<script>') !== -1,
          'explicit-cfg call respects in-call hook widening: ' + withCfg
        );

        purify.removeAllHooks();
        purify.clearConfig();

        assert.equal(
          purify.sanitize('<svg><script>alert(1)</script></svg>'),
          '<svg></svg>',
          'default-cfg call after explicit-cfg+hook is unaffected'
        );
      });
    }
  );

  QUnit.test(
    'sanitize() should allow unknown protocols when ALLOW_UNKNOWN_PROTOCOLS is true',
    function (assert) {
      var dirty =
        '<div><a href="spotify:track:12345"><img src="cid:1234567"></a></div>';
      assert.equal(
        dirty,
        DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
      );
    }
  );

  QUnit.test(
    'sanitize() should not allow javascript when ALLOW_UNKNOWN_PROTOCOLS is true',
    function (assert) {
      var dirty =
        '<div><a href="javascript:alert(document.title)"><img src="cid:1234567"/></a></div>';
      var modified = '<div><a><img src="cid:1234567"></a></div>';
      assert.equal(
        modified,
        DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
      );
    }
  );

  QUnit.test('Regression-Test to make sure #166 stays fixed', function (
    assert
  ) {
    var dirty = '<p onFoo="123">HELLO</p>';
    var modified = '<p>HELLO</p>';
    assert.equal(
      modified,
      DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
    );
  });

  // Test 1 to check if the element count in DOMPurify.removed is correct
  QUnit.test('DOMPurify.removed should contain one element', function (assert) {
    var dirty =
      '<svg onload=alert(1)><filter><feGaussianBlur /></filter></svg>';
    DOMPurify.sanitize(dirty);
    assert.equal(DOMPurify.removed.length, 1);
  });

  // Test 2 to check if the element count in DOMPurify.removed is correct
  QUnit.test('DOMPurify.removed should contain two elements', function (
    assert
  ) {
    var dirty =
      '1<script>alert(1)</script><svg onload=alert(1)><filter><feGaussianBlur /></filter></svg>';
    DOMPurify.sanitize(dirty);
    assert.equal(DOMPurify.removed.length, 2);
  });

  // Test 3 to check if the element count in DOMPurify.removed is correct
  QUnit.test('DOMPurify.removed should be correct', function (assert) {
    var dirty = '<img src=x onerror="alert(1)">';
    DOMPurify.sanitize(dirty);
    assert.equal(DOMPurify.removed.length, 1);
  });

  // Test 4 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
  QUnit.test(
    'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
    function (assert) {
      var dirty = '<a>123{{456}}</a>';
      DOMPurify.sanitize(dirty, {
        WHOLE_DOCUMENT: true,
        SAFE_FOR_TEMPLATES: true,
      });
      assert.equal(DOMPurify.removed.length, 1);
    }
  );

  // Test 5 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
  QUnit.test(
    'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
    function (assert) {
      var dirty = '<a>123{{456}}<b>456{{789}}</b></a>';
      DOMPurify.sanitize(dirty, {
        WHOLE_DOCUMENT: true,
        SAFE_FOR_TEMPLATES: true,
      });
      assert.equal(DOMPurify.removed.length, 2);
    }
  );

  // Test 6 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
  QUnit.test(
    'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
    function (assert) {
      var dirty = '<img src=1 width="{{123}}">';
      DOMPurify.sanitize(dirty, {
        WHOLE_DOCUMENT: true,
        SAFE_FOR_TEMPLATES: true,
      });
      assert.equal(DOMPurify.removed.length, 1);
    }
  );

  // Test 7 to check that DOMPurify.removed is correct in SAFE_FOR_JQUERY mode
  QUnit.test(
    'DOMPurify.removed should be correct in SAFE_FOR_JQUERY mode',
    function (assert) {
      var dirty = '<option><iframe></select><b><script>alert(1)</script>';
      DOMPurify.sanitize(dirty, { SAFE_FOR_JQUERY: true });
      assert.equal(DOMPurify.removed.length, 1);
    }
  );

  // Test 8 to check that DOMPurify.removed is correct if tags are clean
  QUnit.test(
    'DOMPurify.removed should not contain elements if tags are permitted',
    function (assert) {
      var dirty = '<a>123</a>';
      DOMPurify.sanitize(dirty);
      assert.equal(DOMPurify.removed.length, 0);
    }
  );

  // Test 9 to check that DOMPurify.removed is correct if the tags and attributes are clean
  QUnit.test(
    'DOMPurify.removed should not contain elements if all tags and attrs are permitted',
    function (assert) {
      var dirty = '<img src=x>';
      DOMPurify.sanitize(dirty);
      assert.equal(DOMPurify.removed.length, 0);
    }
  );

  // Test 10 to check that DOMPurify.removed does not have false positive elements in SAFE_FOR_TEMLATES mode
  QUnit.test(
    'DOMPurify.removed should not contain elements for valid data in SAFE_FOR_TEMLATES mode',
    function (assert) {
      var dirty = '1';
      DOMPurify.sanitize(dirty, {
        WHOLE_DOCUMENT: true,
        SAFE_FOR_TEMPLATES: true,
      });
      assert.equal(DOMPurify.removed.length, 0);
    }
  );

  // Test 11 to check that DOMPurify.removed does not have false positive elements in SAFE_FOR_JQUERY mode
  QUnit.test(
    'DOMPurify.removed should not contain elements for valid data in SAFE_FOR_JQUERY mode',
    function (assert) {
      var dirty = '1';
      DOMPurify.sanitize(dirty, {
        WHOLE_DOCUMENT: true,
        SAFE_FOR_JQUERY: true,
      });
      assert.equal(DOMPurify.removed.length, 0);
    }
  );
  // Tests to make sure that the node scanning feature delivers acurate results on all browsers
  QUnit.test(
    'DOMPurify should deliver acurate results when sanitizing nodes 1',
    function (assert) {
      var clean = DOMPurify.sanitize(document.createElement('td'));
      assert.equal(clean, '<td></td>');
    }
  );
  QUnit.test(
    'DOMPurify should deliver accurate results when sanitizing nodes 2',
    function (assert) {
      var clean = DOMPurify.sanitize(document.createElement('td'), {
        RETURN_DOM: true,
      });
      assert.equal(clean.outerHTML, '<body><td></td></body>');
    }
  );
  // Test to make sure that URI_safe attributes can be configured too
  QUnit.test('DOMPurify should allow to define URI safe attributes', function (
    assert
  ) {
    var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
      ALLOWED_ATTR: ['typeof'],
      ADD_URI_SAFE_ATTR: ['typeof'],
    });
    assert.equal(clean, '<b typeof="bla:h">123</b>');
  });
  // Test to make sure that URI_safe attributes don't persist, see #327
  QUnit.test('DOMPurify should not persist URI safe attributes', function (
    assert
  ) {
    var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
      ALLOWED_ATTR: ['typeof'],
      ADD_URI_SAFE_ATTR: ['typeof'],
    });
    var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
      ALLOWED_ATTR: ['typeof'],
    });
    assert.equal(clean, '<b>123</b>');
  });
  // Test to make sure that URI_safe attributes don't overwrite default, see #366
  QUnit.test(
    'DOMPurify should not overwrite default URI safe attributes',
    function (assert) {
      var clean = DOMPurify.sanitize(
        '<div poster="x:y" style="color: red">Test</div>',
        { ADD_URI_SAFE_ATTR: ['poster'] }
      );
      assert.contains(clean, [
        '<div style="color: red" poster="x:y">Test</div>',
        '<div style="color: red;" poster="x:y">Test</div>',
      ]);

      clean = DOMPurify.sanitize(
        '<div poster="x:y" style="color: red">Test</div>'
      );
      assert.contains(clean, [
        '<div style="color: red">Test</div>',
        '<div style="color: red;">Test</div>',
      ]);
    }
  );
  // Test to make sure that empty HTML doesn't return null on MSIE11 (#198)
  QUnit.test(
    "Empty HTML shouldn't return null on MSIE11 in RETURN_DOM_FRAGMENT mode",
    function (assert) {
      var clean = DOMPurify.sanitize('', {
        RETURN_DOM: true,
        RETURN_DOM_FRAGMENT: true,
      });
      assert.equal(typeof clean, 'object');
    }
  );
  // Tests to make sure that FORCE_BODY pushes elements to document.body (#199)
  QUnit.test(
    'FORCE_BODY needs to push some elements to document.body',
    function (assert) {
      var clean = DOMPurify.sanitize('<style>123</style>', {
        FORCE_BODY: true,
      });
      assert.equal(clean, '<style>123</style>');
    }
  );
  QUnit.test(
    'FORCE_BODY needs to push some elements to document.body',
    function (assert) {
      var clean = DOMPurify.sanitize('<script>123</script>', {
        FORCE_BODY: true,
        ADD_TAGS: ['script'],
      });
      assert.equal(clean, '<script>123</script>');
    }
  );
  QUnit.test(
    'FORCE_BODY needs to push some elements to document.body',
    function (assert) {
      var clean = DOMPurify.sanitize(' AAAAA', { FORCE_BODY: true });
      assert.equal(clean, ' AAAAA');
    }
  );
  QUnit.test('Lack of FORCE_BODY still preserves leading whitespace', function (
    assert
  ) {
    var clean = DOMPurify.sanitize(' <b>AAAAA</b>', { FORCE_BODY: false });
    assert.equal(clean, ' <b>AAAAA</b>');
  });
  QUnit.test(
    'Lack of FORCE_BODY needs to push some elements to document.head',
    function (assert) {
      var clean = DOMPurify.sanitize('<style>123</style>', {
        FORCE_BODY: false,
      });
      assert.equal(clean, '');
    }
  );
  // Test to make sure that ALLOW_ARIA_ATTR is working as expected (#198)
  QUnit.test('Config-Flag tests: ALLOW_ARIA_ATTR', function (assert) {
    assert.contains(
      DOMPurify.sanitize('<a aria-abc="foo" href="#">abc</a>', {
        ALLOW_ARIA_ATTR: true,
      }),
      [
        '<a aria-abc="foo" href="#">abc</a>',
        '<a href="#" aria-abc="foo">abc</a>',
      ]
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" aria-aöü="foo">abc</a>', {
        ALLOW_ARIA_ATTR: true,
      }),
      '<a href="#">abc</a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" aria-abc="foo">abc</a>', {
        ALLOW_ARIA_ATTR: false,
      }),
      '<a href="#">abc</a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" aria-äöü="foo">abc</a>', {
        ALLOW_ARIA_ATTR: false,
      }),
      '<a href="#">abc</a>'
    );
  });
  QUnit.test('Config-Flag tests: USE_PROFILES', function (assert) {
    assert.equal(
      DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { html: false } }),
      'HELLO'
    );
    assert.equal(
      DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { html: true } }),
      '<h1>HELLO</h1>'
    );
    assert.contains(
      DOMPurify.sanitize('<h1>HELLO</h1><math></math>', {
        USE_PROFILES: { html: true, mathMl: true },
      }),
      ['<h1>HELLO</h1>', '<h1>HELLO</h1><math></math>']
    );
    assert.contains(
      DOMPurify.sanitize('<h1>HELLO</h1><math><mi></mi></math>', {
        USE_PROFILES: { html: true, mathMl: true },
      }),
      ['<h1>HELLO</h1>', '<h1>HELLO</h1><math><mi></mi></math>']
    );
    assert.contains(
      DOMPurify.sanitize('<h1>HELLO</h1><math><mi></mi></math>', {
        USE_PROFILES: { html: true, mathMl: true },
        FORBID_TAGS: ['mi'],
      }),
      ['<h1>HELLO</h1>', '<h1>HELLO</h1><math></math>']
    );
    assert.contains(
      DOMPurify.sanitize('<h1>HELLO</h1><math class="foo"><mi></mi></math>', {
        USE_PROFILES: { html: true, mathMl: true },
        FORBID_ATTR: ['class'],
      }),
      ['<h1>HELLO</h1>', '<h1>HELLO</h1><math><mi></mi></math>']
    );
    assert.equal(
      DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { bogus: true } }),
      'HELLO'
    );
    assert.equal(
      DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: 123 }),
      'HELLO'
    );
    assert.equal(
      DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: [] }),
      'HELLO'
    );
    assert.contains(
      DOMPurify.sanitize('<svg><rect height="50"></rect></svg>', {
        USE_PROFILES: { svg: true },
      }),
      [
        '',
        '<svg><rect height="50"></rect></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg"><rect height="50" /></svg>',
      ]
    );
    assert.contains(
      DOMPurify.sanitize('<feBlend in="SourceGraphic" mode="multiply" />', {
        USE_PROFILES: { svgFilters: true },
      }),
      [
        '<feblend in="SourceGraphic" mode="multiply"></feblend>',
        '<feblend mode="multiply" in="SourceGraphic"></feblend>',
      ]
    );
    assert.contains(
      DOMPurify.sanitize('<svg><style>.some-class {fill: #fff}</style></svg>', {
        USE_PROFILES: { svg: true },
      }),
      [
        '',
        '<svg><style>.some-class {fill: #fff}</style></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg"><style>.some-class {fill: #fff}</style></svg>',
      ]
    );
    assert.contains(
      DOMPurify.sanitize('<svg><text>SEE ME</text></svg>', {
        USE_PROFILES: { svg: true },
        KEEP_CONTENT: false,
      }),
      [
        '',
        '<svg><text>SEE ME</text></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg"><text>SEE ME</text></svg>',
      ]
    );
    assert.equal(
      DOMPurify.sanitize('<span>SEE ME</span>', {
        USE_PROFILES: { html: true },
        KEEP_CONTENT: false,
      }),
      '<span>SEE ME</span>'
    );
    assert.equal(
      DOMPurify.sanitize('<div></div>', {
        USE_PROFILES: { svg: true },
        ADD_TAGS: ['div'],
      }),
      '<div></div>'
    );
    assert.contains(
      DOMPurify.sanitize('<svg keep="me"></svg>', {
        USE_PROFILES: { svg: true },
        ADD_ATTR: ['keep'],
      }),
      [
        '',
        '<svg keep="me"></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg" keep="me" />',
      ]
    );
  });
  QUnit.test(
    'Config-Flag tests: USE_PROFILES ALLOWED_ATTR is prototype-free',
    function (assert) {
      // Inherited Array.prototype members must not count as allowed attributes
      assert.equal(
        DOMPurify.sanitize('<img fill="x" map="x" filter="x" src="x">', {
          USE_PROFILES: {},
          ADD_TAGS: ['img'],
        }),
        '<img>'
      );
      assert.equal(
        DOMPurify.sanitize('<img fill="x" map="x" filter="x" src="x">', {
          USE_PROFILES: { html: false },
          ADD_TAGS: ['img'],
        }),
        '<img>'
      );

      // Persistent configuration and isValidAttribute() share the same set
      try {
        DOMPurify.setConfig({ USE_PROFILES: {}, ADD_TAGS: ['img'] });
        assert.equal(DOMPurify.isValidAttribute('img', 'map', 'x'), false);
        assert.equal(DOMPurify.sanitize('<img fill="x" src="x">'), '<img>');
      } finally {
        DOMPurify.clearConfig();
      }

      // Polluted Object.prototype must not allow event handlers
      var clean;
      try {
        Object.defineProperty(Object.prototype, 'onerror', {
          value: true,
          writable: true,
          configurable: true,
        });
        clean = DOMPurify.sanitize('<img src="x" onerror="alert(1)">', {
          USE_PROFILES: {},
          ADD_TAGS: ['img'],
          FORBID_ATTR: ['style'],
        });
      } finally {
        delete Object.prototype.onerror;
        DOMPurify.clearConfig();
      }

      assert.equal(clean, '<img>');
    }
  );
  QUnit.test('Config-Flag tests: ALLOWED_URI_REGEXP', function (assert) {
    var tests = [
      {
        test: '<img src="https://i.imgur.com/hkfpOUu.gifv">',
        expected: '<img src="https://i.imgur.com/hkfpOUu.gifv">',
      },
      {
        test: '<img src="http://i.imgur.com/WScAnHr.jpg">',
        expected: '<img src="http://i.imgur.com/WScAnHr.jpg">',
      },
      {
        test:
          '<img src="blob:https://localhost:3000/c4ea3ec6-9f22-4d08-af6f-d79e78a0a7a7">',
        expected: '<img>',
      },
      {
        test: '<a href="mailto:demo@example.com">demo</a>',
        expected: '<a>demo</a>',
      },
    ].forEach(function (test) {
      var str = DOMPurify.sanitize(test.test, {
        ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i,
      });
      assert.equal(str, test.expected);
    });
  });
  QUnit.test('Avoid freeze when using tables and ALLOW_TAGS', function (
    assert
  ) {
    var clean = DOMPurify.sanitize('<table><tr><td></td></tr></table>', {
      ALLOW_TAGS: ['table', 'tr', 'td'],
    });
    assert.equal(clean, '<table><tbody><tr><td></td></tr></tbody></table>');
  });
  QUnit.test(
    'Avoid XSS with ALLOW_TAGS permitting noembed, noscript',
    function (assert) {
      var clean = DOMPurify.sanitize(
        "a<noembed><p id='</noembed><img src=x onerror=alert(1)>'></p></noembed>",
        { ADD_TAGS: ['noembed'] }
      );
      assert.contains(clean, [
        'a<noembed><p id=\'</noembed><img src="x">\'&gt;<p></p>',
        'a',
        'a<noembed>&lt;p id=\'</noembed><img src="x">\'&gt;<p></p>',
        'a<noembed><p id="&lt;/noembed&gt;&lt;img src=x onerror=alert(1)&gt;"></p></noembed>',
        'a<noembed></noembed>',
        'a<noembed><p></p></noembed>',
      ]);
    }
  );
  QUnit.test('Avoid mXSS in Chrome 77 and above using SVG', function (assert) {
    var clean = DOMPurify.sanitize('<svg></p><style><g title="</style>');
    assert.contains(clean, [
      '',
      '<svg><p></p><style></style></svg>',
      '<svg></svg><p></p><style><g title="</style>',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p><style /></svg></svg>',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p><style /></svg>',
      '<p></p><style><g title="</style>',
    ]);
  });
  QUnit.test('Avoid mXSS in Chrome 77 and above using HTML', function (assert) {
    var clean = DOMPurify.sanitize('<svg></p><title><a href="</title>qqq');
    assert.contains(clean, [
      '',
      '<svg><p></p><title></title></svg>',
      '<svg></svg><p></p><title>&lt;a href="</title>qqq<img src="">"&gt;',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p><title /></svg>',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p><style /></svg>',
      '<svg></svg><p></p><title>&lt;a href="</title>qqq',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p><title /></svg></svg>',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p></svg>',
      '<p></p><title>&lt;a href="</title>qqq',
    ]);
  });
  QUnit.test(
    'Test for correct return value when RETURN_TRUSTED_TYPE is true',
    function (assert) {
      var clean = DOMPurify.sanitize('<b>hello goodbye</b>', {
        RETURN_TRUSTED_TYPE: true,
      });
      var type = typeof clean;
      assert.contains(type, ['TrustedHTML', 'string', 'object']);
    }
  );
  QUnit.test(
    'Test for correct return value when RETURN_TRUSTED_TYPE is false',
    function (assert) {
      var clean = DOMPurify.sanitize('<b>hello goodbye</b>', {
        RETURN_TRUSTED_TYPE: false,
      });
      var type = typeof clean;
      assert.equal(type, 'string');
    }
  );
  QUnit.test(
    'Test for correct return value when RETURN_TRUSTED_TYPE is not set',
    function (assert) {
      var clean = DOMPurify.sanitize('<b>hello goodbye</b>');
      var type = typeof clean;
      assert.equal(type, 'string');
    }
  );
  QUnit.test(
    'Test for DoS coming from table sanitization 1/2 See #365',
    function (assert) {
      var config = { FORBID_TAGS: ['tbody'] };
      var clean = DOMPurify.sanitize(
        '<table><tbody><tr><td>test</td></tr></tbody></table>',
        config
      );
      assert.equal(
        clean,
        '<table><tbody><tr><td>test</td></tr></tbody></table>'
      );
    }
  );
  QUnit.test(
    'Test for DoS coming from table sanitization 2/2 See #365',
    function (assert) {
      var config = {
        ALLOWED_TAGS: [
          'b',
          'strong',
          'i',
          'italic',
          'div',
          'p',
          'span',
          'ul',
          'li',
          'ol',
          'a',
          'img',
          'br',
          'tr',
          'td',
          'th',
          'table',
          'h1',
          'h2',
          'h3',
          'h4',
          'h5',
          'h6',
        ],
        ALLOW_DATA_ATTR: false,
        ALLOWED_ATTR: ['src', 'class', 'target', 'href'],
      };
      var clean = DOMPurify.sanitize(
        '<table><colgroup><col></col></colgroup><tbody><tr><td >test</td></tr></tbody></table>',
        config
      );
      assert.equal(
        clean,
        '<table><tbody><tr><td>test</td></tr></tbody></table>'
      );
    }
  );
  QUnit.test('Test for less agressive mXSS handling, See #369', function (
    assert
  ) {
    var config = {
      FORBID_TAGS: ['svg', 'math'],
    };
    var clean = DOMPurify.sanitize(
      '<b data-test="<span>content</span>"></b>',
      config
    );
    assert.contains(clean, [
      '<b data-test="<span>content</span>"></b>',
      '<b data-test="&lt;span&gt;content&lt;/span&gt;"></b>',
    ]);
  });
  QUnit.test(
    'Test against mXSS using text integration points and removal 1/2',
    function (assert) {
      var config = {
        FORBID_TAGS: ['mi'],
      };
      var clean = DOMPurify.sanitize(
        '<math><mi><b><style><b title="</style><iframe onload&#x3d;alert(1)<!--"></style>',
        config
      );
      assert.contains(clean, [
        '<math><b><style><b title="</style></b></math>',
        '<math></math>',
      ]);
    }
  );
  QUnit.test(
    'Test against mXSS using text integration points and removal 2/2',
    function (assert) {
      var config = {
        ADD_TAGS: ['xmp'],
      };
      var clean = DOMPurify.sanitize(
        "x<noframes><svg><b><xmp><b title='</xmp><img>",
        config
      );
      assert.contains(clean, ['x']);
    }
  );
  QUnit.test(
    'Test against insecure behavior in jQUery v3.0 and newer 1/2',
    function (assert) {
      var config = {
        SAFE_FOR_JQUERY: true,
      };
      var clean = DOMPurify.sanitize(
        '<img x="/><img src=x onerror=alert(1)>" y="<x">',
        config
      );
      assert.contains(clean, [
        '<img y="<x" x="/><img src=x onerror=alert(1)>">', // jsdom
        '<img y="<x">',
        '<img y="&lt;x">',
        '<img y="<x">',
      ]);
    }
  );
  QUnit.test(
    'Test against insecure behavior in jQUery v3.0 and newer 2/2',
    function (assert) {
      var config = {
        SAFE_FOR_JQUERY: true,
        ADD_TAGS: ['noscript'],
      };
      var clean = DOMPurify.sanitize(
        "a<noscript><p id='><noscript /><img src=x onerror=alert(1)>'></noscript>",
        config
      );
      assert.contains(clean, [
        "a<noscript>&lt;p id='>&lt;noscript />&lt;img src=x onerror=alert(1)>'></noscript>", // jsdom
        'a<noscript><p></p></noscript>',
      ]);
    }
  );
  QUnit.test(
    'Test against data URIs in anchors without proper config flag',
    function (assert) {
      var clean = DOMPurify.sanitize('<a href="data:image/gif;base64,123">icon.gif</a>');
      assert.equal(clean, '<a>icon.gif</a>');
    }
  );
  QUnit.test(
    'Test against data URIs in anchors using proper config flag',
    function (assert) {
      var clean = DOMPurify.sanitize('<a href="data:image/gif;base64,123">icon.gif</a>', {
          ADD_DATA_URI_TAGS: ['a', 'b']
      });
      assert.equal(clean, '<a href="data:image/gif;base64,123">icon.gif</a>');
    }
  );
  QUnit.test(
    'Test nesting depth limit inside template content (mXSS)',
    function (assert) {
      var repeat = function (str, times) {
        return new Array(times + 1).join(str);
      };
      var wrap = function (html) {
        return '<div><template>' + html + '</template></div>';
      };

      // The template content continues counting from the template's own
      // depth (body > div > template = 3)

      // Nesting below the maximum depth is left untouched
      var dirty = wrap(repeat('<div>', 250) + repeat('</div>', 250));
      assert.equal(DOMPurify.sanitize(dirty), dirty);

      dirty = wrap(repeat('<div>', 251) + repeat('</div>', 251));
      assert.equal(DOMPurify.sanitize(dirty), dirty);

      // Elements reaching the maximum depth are removed
      var expected = wrap(repeat('<div>', 251) + repeat('</div>', 251));
      dirty = wrap(repeat('<div>', 252) + repeat('</div>', 252));
      assert.equal(DOMPurify.sanitize(dirty), expected);

      dirty = wrap(
        repeat('<div>', 600) +
          '<img src=x onerror=alert(1)>' +
          repeat('</div>', 600)
      );
      assert.equal(DOMPurify.sanitize(dirty), expected);
    }
  );
  QUnit.test(
    'Test nesting depth propagation across nested template content (mXSS)',
    function (assert) {
      var repeat = function (str, times) {
        return new Array(times + 1).join(str);
      };

      // The inner template content must not restart counting at zero
      var dirty =
        '<div><template>' +
        repeat('<div>', 200) +
        '<template>' +
        repeat('<div>', 200) +
        '<img src=x onerror=alert(1)>' +
        repeat('</div>', 200) +
        '</template>' +
        repeat('</div>', 200) +
        '</template></div>';
      var expected =
        '<div><template>' +
        repeat('<div>', 200) +
        '<template>' +
        repeat('<div>', 50) +
        repeat('</div>', 50) +
        '</template>' +
        repeat('</div>', 200) +
        '</template></div>';
      assert.equal(DOMPurify.sanitize(dirty), expected);
    }
  );
  QUnit.test(
    'Test nesting depth tampering via prototype pollution',
    function (assert) {
      var repeat = function (str, times) {
        return new Array(times + 1).join(str);
      };

      // Find the Object.prototype that DOM nodes actually inherit from
      var objectPrototype = document.createDocumentFragment();
      while (Object.getPrototypeOf(objectPrototype) !== null) {
        objectPrototype = Object.getPrototypeOf(objectPrototype);
      }

      var sanitizePolluted = function (dirty, pollution) {
        var keys = Object.keys(pollution);
        var i;
        for (i = 0; i < keys.length; i++) {
          Object.defineProperty(objectPrototype, keys[i], {
            value: pollution[keys[i]],
            writable: true,
            configurable: true,
          });
        }

        try {
          return DOMPurify.sanitize(dirty);
        } finally {
          for (i = 0; i < keys.length; i++) {
            delete objectPrototype[keys[i]];
          }
        }
      };

      var dirty =
        '<div><template>' +
        repeat('<div>', 600) +
        '<img src=x onerror=alert(1)>' +
        repeat('</div>', 600) +
        '</template></div>';

      // Negative depth inherited by the elements of the document
      assert.equal(sanitizePolluted(dirty, { __depth: -1000 }), '');
      assert.equal(sanitizePolluted(dirty, { __removalCount: -1000 }), '');

      // Depth turned into NaN (Infinity + -Infinity) or Infinity
      assert.equal(
        sanitizePolluted(dirty, { __depth: -Infinity, __removalCount: Infinity }),
        '<div></div>'
      );

      // Non-numeric depth makes every element look clobbered
      assert.equal(sanitizePolluted(dirty, { __depth: '-1000' }), '');
      assert.equal(sanitizePolluted(dirty, { __removalCount: '-1000' }), '');

      // Back to normal once the pollution is gone
      assert.equal(
        DOMPurify.sanitize(dirty),
        '<div><template>' +
          repeat('<div>', 251) +
          repeat('</div>', 251) +
          '</template></div>'
      );
    }
  );
  QUnit.test(
    'Test nesting depth tampering via DOM clobbering',
    function (assert) {
      var repeat = function (str, times) {
        return new Array(times + 1).join(str);
      };
      var names = ['__depth', '__removalCount'];
      for (var i = 0; i < names.length; i++) {
        var clean = DOMPurify.sanitize(
          '<div><template><form><input name="' +
            names[i] +
            '">' +
            repeat('<div>', 600) +
            '<img src=x onerror=alert(1)>' +
            repeat('</div>', 600) +
            '</form></template></div>'
        );
        assert.contains(clean, [
          '<div><template></template></div>',
          // No named form properties (jsdom)
          '<div><template><form><input name="' +
            names[i] +
            '">' +
            repeat('<div>', 250) +
            repeat('</div>', 250) +
            '</form></template></div>',
        ]);
      }
    }
  );
  QUnit.test(
    'Test protection from prototype pollution attacks 1/2',
    function (assert) {
      var obj = JSON.parse(
        '{"ALLOWED_ATTR":["onerror","src"], "documentMode":9}'
      );
      var keys = Object.keys(obj);
      var i;
      var clean;
      try {
        for (i = 0; i < keys.length; i++) {
          Object.prototype[keys[i]] = obj[keys[i]];
        }
        clean = DOMPurify.sanitize('<img src=x onerror=alert(1)>');
      } finally {
        for (i = 0; i < keys.length; i++) {
          delete Object.prototype[keys[i]];
        }
      }
      assert.equal(clean, '<img src="x">');
    }
  );
  QUnit.test(
    'Test protection from prototype pollution attacks 2/2',
    function (assert) {
      var obj = {};
      /* Ignore IE10 issue */
      if (obj.__proto__ === undefined) {
        assert.equal(1, 1);
        return true;
      }
      var originalHasOwnProperty = obj.__proto__.hasOwnProperty;
      var clean;
      try {
        obj.__proto__.hasOwnProperty = Object;
        obj.constructor.prototype.ALLOWED_ATTR = ['src', 'onerror'];
        clean = DOMPurify.sanitize('<img src=x onerror=alert(1)>');
      } finally {
        obj.__proto__.hasOwnProperty = originalHasOwnProperty;
        delete obj.constructor.prototype.ALLOWED_ATTR;
      }
      assert.equal(clean, '<img src="x">');
    }
  );
  QUnit.test(
    'Test proper handling of nesting-based mXSS 1/3',
    function (assert) {
      var repeat = function (str, times) {
        return new Array(times + 1).join(str);
      };

      var dirty = repeat('<div>', 250) + repeat('</div>', 250) + '<img>';
      var expected = repeat('<div>', 250) + repeat('</div>', 250) + '<img>';
      assert.equal(DOMPurify.sanitize(dirty), expected);

      dirty = repeat('<div>', 255) + repeat('</div>', 255) + '<img>';
      expected = repeat('<div>', 253) + repeat('</div>', 253) + '<img>';
      assert.equal(DOMPurify.sanitize(dirty), expected);

      dirty = repeat('<div>', 257) + repeat('</div>', 257) + '<img>';
      expected = repeat('<div>', 253) + repeat('</div>', 253) + '<img>';
      assert.equal(DOMPurify.sanitize(dirty), expected);

      dirty =
        repeat('<div>', 600) +
        '<img src=x onerror=alert(1)>' +
        repeat('</div>', 600);
      expected = repeat('<div>', 253) + repeat('</div>', 253);
      assert.equal(DOMPurify.sanitize(dirty), expected);

      dirty =
        '<div><template>' +
        repeat('<div>', 257) +
        repeat('</div>', 257) +
        '<img>';
      expected =
        '<div><template>' +
        repeat('<div>', 251) +
        repeat('</div>', 251) +
        '<img></template></div>';
      assert.equal(DOMPurify.sanitize(dirty), expected);

      dirty =
        '<div><template>' +
        repeat('<r>', 255) +
        '<img>' +
        repeat('</r>', 255) +
        '</template></div><img>';
      expected = [
        '<div><template></template></div><img>',
        '<div><template><html><head></head><body></body></html></template></div><img>',
        '<div><template><head></head><body></body></template></div><img>',
      ];
      assert.contains(DOMPurify.sanitize(dirty), expected);
    }
  );
  QUnit.test(
    'Test proper handling of nesting-based mXSS 2/3',
    function (assert) {
      var repeat = function (str, times) {
        return new Array(times + 1).join(str);
      };

      var dirty =
        '<form><input name="__depth">' +
        repeat('<div>', 500) +
        repeat('</div>', 500) +
        '<img>';
      var expected = [
        '',
        '<form><input name="__depth">' +
          repeat('<div>', 252) +
          repeat('</div>', 252) +
          '<img></form>',
      ];
      assert.contains(DOMPurify.sanitize(dirty), expected);

      dirty =
        '<form><input name="__depth"></form>' +
        repeat('<div>', 500) +
        repeat('</div>', 500) +
        '<img>';
      expected = [
        repeat('<div>', 253) + repeat('</div>', 253) + '<img>',
        '<form><input name="__depth"></form>' +
          repeat('<div>', 253) +
          repeat('</div>', 253) +
          '<img>',
      ];
      assert.contains(DOMPurify.sanitize(dirty), expected);

      dirty =
        '<form><input name="__removalCount">' +
        repeat('<div>', 500) +
        repeat('</div>', 500) +
        '<img>';
      expected = [
        '',
        '<form><input name="__removalCount">' +
          repeat('<div>', 252) +
          repeat('</div>', 252) +
          '<img></form>',
      ];
      assert.contains(DOMPurify.sanitize(dirty), expected);

      dirty =
        '<form><input name="__removalCount"></form>' +
        repeat('<div>', 500) +
        repeat('</div>', 500) +
        '<img>';
      expected = [
        repeat('<div>', 253) + repeat('</div>', 253) + '<img>',
        '<form><input name="__removalCount"></form>' +
          repeat('<div>', 253) +
          repeat('</div>', 253) +
          '<img>',
      ];
      assert.contains(DOMPurify.sanitize(dirty), expected);
    }
  );
  QUnit.test(
    'Test proper handling of nesting-based mXSS 3/3',
    function (assert) {
      var dirty = '<form><input name="__depth">';
      var expected = ['', '<form><input name="__depth"></form>'];
      assert.contains(DOMPurify.sanitize(dirty), expected);

      dirty = '<form><input name="__removalCount">';
      expected = ['', '<form><input name="__removalCount"></form>'];
      assert.contains(DOMPurify.sanitize(dirty), expected);
    }
  );
  QUnit.test(
    'Test nesting depth of content hoisted by KEEP_CONTENT (mXSS)',
    function (assert) {
      var repeat = function (str, times) {
        return new Array(times + 1).join(str);
      };

      // Every node a removed element leaves behind keeps the depth it had
      // in the original tree, not just the first one
      var dirty =
        repeat('<x>a', 260) +
        '<div><img src=x onerror=alert(1)></div>' +
        repeat('</x>', 260);
      assert.equal(DOMPurify.sanitize(dirty), repeat('a', 260));

      // A clobbered node among the hoisted ones must not stop the counting
      dirty =
        repeat('<x><form><input name="__removalCount"></form>', 260) +
        '<div><img src=x onerror=alert(1)></div>' +
        repeat('</x>', 260);
      var clean = DOMPurify.sanitize(dirty);
      assert.equal(clean.indexOf('<div'), -1);
      assert.equal(clean.indexOf('<img'), -1);
    }
  );
  QUnit.test(
    'Test against nesting-based mXSS via nested form and table elements',
    function (assert) {
      // Parse the sanitized markup again in an inert document, just like
      // assigning it to innerHTML would, and look for elements that only
      // show up after the namespace confusion of the round trip
      var reparse = function (html) {
        var doc = document.implementation.createHTMLDocument('');
        doc.body.innerHTML = html;
        return doc.body;
      };

      var payloads = [
        '<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>',
        '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
      ];
      for (var i = 0; i < payloads.length; i++) {
        var body = reparse(DOMPurify.sanitize(payloads[i]));
        assert.equal(
          body.querySelectorAll('img').length,
          0,
          'Payload: ' + payloads[i]
        );
        assert.equal(
          body.querySelectorAll('[onerror]').length,
          0,
          'Payload: ' + payloads[i]
        );
      }
    }
  );
  QUnit.test(
    'Test against mXSS via raw-text closing tags inside attributes (CVE-2026-65914)',
    function (assert) {
      // Parse the sanitized markup again in an inert document, wrapped in
      // the raw-text element the attribute value tries to close
      var reparse = function (html) {
        var doc = document.implementation.createHTMLDocument('');
        doc.body.innerHTML = html;
        return doc.body;
      };

      var tags = [
        'script',
        'xmp',
        'textarea',
        'noscript',
        'iframe',
        'noembed',
        'noframes',
        'style',
        'title',
      ];
      for (var i = 0; i < tags.length; i++) {
        var tag = tags[i];
        var dirty = '<img alt="</' + tag + '><img src=x onerror=alert(1)>">';
        var clean = DOMPurify.sanitize(dirty);
        assert.equal(clean, '<img>', 'Payload: ' + dirty);

        var body = reparse('<' + tag + '>' + clean + '</' + tag + '>');
        assert.equal(
          body.querySelectorAll('[onerror]').length,
          0,
          'Reparsed inside <' + tag + '>: ' + clean
        );

        // Closing tags are matched case-insensitively
        dirty =
          '<a title="</' +
          tag.toUpperCase() +
          '><img src=x onerror=alert(1)>">x</a>';
        assert.equal(
          DOMPurify.sanitize(dirty),
          '<a>x</a>',
          'Payload: ' + dirty
        );
      }

      // DOMPurify parses <noscript> content as markup, while a browser with
      // scripting enabled treats it as raw text once the output is rendered
      dirty =
        '<b><noscript><a alt="</noscript><img src=x onerror=alert(1)>"></noscript>';
      assert.contains(
        DOMPurify.sanitize(dirty),
        ['<b><a></a></b>', '<b></b>', '<b><img src="x">"&gt;</b>'],
        'Payload: ' + dirty
      );

      // Attribute values without raw-text closing tags are kept
      assert.equal(
        DOMPurify.sanitize('<img alt="script / xmp / textarea">'),
        '<img alt="script / xmp / textarea">'
      );
      assert.contains(DOMPurify.sanitize('<img alt="</b>">'), [
        '<img alt="</b>">',
        '<img alt="&lt;/b&gt;">',
      ]);
    }
  );

  // ---------------------------------------------------------------------------
  // CVE-2026-49459 (GHSA-r47g-fvhr-h676) - parent-less clobbered IN_PLACE root
  // retains attacker-controlled attributes. When _forceRemove can't detach the
  // root (no parent), any event-handler attribute on the root survives.
  // sanitize() must instead throw on a clobbered IN_PLACE root.
  // ---------------------------------------------------------------------------

  // Does this engine implement HTMLFormElement [LegacyOverrideBuiltIns]
  // named-property clobbering for the given name? (jsdom does not)
  var formClobbers = function (name, tagName) {
    var form = document.createElement('form');
    var control = document.createElement(tagName || 'input');
    control.setAttribute('name', name);
    form.appendChild(control);
    return form[name] === control;
  };

  QUnit.test(
    'Config-Flag tests: IN_PLACE handles DOM-clobbered nodeName safely (CVE-2026-49459)',
    function (assert) {
      // Build the clobbering candidate.
      var root = document.createElement('form');
      root.innerHTML =
        '<input name="nodeName" onclick="alert(1)">' +
        '<input name="attributes" onclick="alert(2)">';

      var clobbersNodeName = typeof root.nodeName !== 'string';

      if (clobbersNodeName) {
        assert.throws(
          function () {
            DOMPurify.sanitize(root, { IN_PLACE: true });
          },
          /clobbered/i,
          'clobbered IN_PLACE root must throw in clobbering-capable engines'
        );
      } else {
        var clean = DOMPurify.sanitize(root, { IN_PLACE: true });
        assert.ok(
          !/on\w+=/i.test(clean.outerHTML),
          'no on-handler survived: ' + clean.outerHTML
        );
      }
    }
  );

  QUnit.test(
    'CVE-2026-49459: parent-less clobbered form root throws instead of returning the root with onmouseover intact',
    function (assert) {
      if (!formClobbers('nodeName')) {
        assert.ok(true, 'SKIP: no form clobbering in this engine');
        return;
      }

      // The report's PoC: parent-less <form onmouseover=...> with an
      // <input name="nodeName"> child that clobbers form.nodeName. The throw
      // IS the protection: by refusing to return the root, the sanitizer
      // makes it impossible for the caller to insert an attacker-controlled
      // element into the live DOM.
      var root = document.createElement('form');
      root.setAttribute('onmouseover', 'window.__rooted_h676 = 1');
      var clobber = document.createElement('input');
      clobber.setAttribute('name', 'nodeName');
      root.appendChild(clobber);

      var result = null;
      assert.throws(
        function () {
          result = DOMPurify.sanitize(root, { IN_PLACE: true });
        },
        /root node is clobbered/,
        'clobbered parent-less IN_PLACE root must throw'
      );
      assert.equal(result, null, 'no node is handed back to the caller');
    }
  );

  QUnit.test(
    'CVE-2026-49459: each clobbering name covered by _isClobbered triggers the IN_PLACE preamble throw',
    function (assert) {
      // Every name _isClobbered checks on this version. Any one of them
      // flags the root, which _forceRemove can't detach, so each must make
      // the IN_PLACE preamble throw.
      var clobberNames = [
        'nodeName',
        'textContent',
        'removeChild',
        'attributes',
        'removeAttribute',
        'setAttribute',
        'namespaceURI',
        'insertBefore',
        'hasChildNodes',
        'childNodes',
        'nodeType',
        '__depth',
        '__removalCount',
      ];

      for (var i = 0; i < clobberNames.length; i++) {
        var name = clobberNames[i];
        if (!formClobbers(name)) {
          assert.ok(true, 'SKIP: no form clobbering of "' + name + '"');
          continue;
        }

        var root = document.createElement('form');
        root.setAttribute('onmouseover', 'window.__rooted_' + name + ' = 1');
        root.setAttribute('action', 'javascript:alert(1)');
        var clobber = document.createElement('input');
        clobber.setAttribute('name', name);
        root.appendChild(clobber);

        assert.throws(
          function () {
            DOMPurify.sanitize(root, { IN_PLACE: true });
          },
          /root node is clobbered/,
          'IN_PLACE preamble must throw for clobber name="' + name + '"'
        );

        // Re-sanitizing the same node must still refuse it
        assert.throws(
          function () {
            DOMPurify.sanitize(root, {
              IN_PLACE: true,
              SAFE_FOR_TEMPLATES: true,
            });
          },
          /root node is clobbered/,
          'second IN_PLACE pass must throw for clobber name="' + name + '"'
        );
      }
    }
  );

  QUnit.test(
    'CVE-2026-49459: a parented clobbered form is still sanitized normally (regression guard)',
    function (assert) {
      if (!formClobbers('nodeName')) {
        assert.ok(true, 'SKIP: no form clobbering in this engine');
        return;
      }

      // When the IN_PLACE root is NOT the clobbered form (it's a wrapper
      // that contains it), the iterator-driven removal path works normally:
      // _forceRemove succeeds because the form has a parent.
      var wrapper = document.createElement('div');
      var form = document.createElement('form');
      form.setAttribute('onmouseover', 'window.__rooted_parented = 1');
      var clobber = document.createElement('input');
      clobber.setAttribute('name', 'nodeName');
      form.appendChild(clobber);
      wrapper.appendChild(form);

      DOMPurify.sanitize(wrapper, { IN_PLACE: true });

      assert.equal(
        wrapper.querySelectorAll('form').length,
        0,
        'parented clobbered form is removed by the iterator-driven path'
      );
    }
  );

  QUnit.test(
    'CVE-2026-49459: _isClobbered: form with name="childNodes" child is removed during sanitization',
    function (assert) {
      if (!formClobbers('childNodes')) {
        assert.ok(true, 'SKIP: no form clobbering in this engine');
        return;
      }

      var form = document.createElement('form');
      var clobber = document.createElement('input');
      clobber.setAttribute('name', 'childNodes');
      form.appendChild(clobber);

      var wrapper = document.createElement('div');
      wrapper.appendChild(form);

      DOMPurify.sanitize(wrapper, { IN_PLACE: true });

      assert.equal(
        wrapper.querySelectorAll('form').length,
        0,
        'clobbered form must be removed'
      );
    }
  );

  QUnit.test(
    'CVE-2026-49459: _isClobbered: form clobbered by <select name="childNodes"> is still removed',
    function (assert) {
      // <select> defeats a naive `typeof childNodes.length === "number"`
      // probe because HTMLSelectElement.length is a defined unsigned-long
      // attribute returning the option count. The probe must instead compare
      // the direct read against the cached Node.prototype getter, which is
      // type-agnostic and catches every clobbering child.
      if (!formClobbers('childNodes', 'select')) {
        assert.ok(true, 'SKIP: no form clobbering in this engine');
        return;
      }

      var form = document.createElement('form');
      var clobber = document.createElement('select');
      clobber.setAttribute('name', 'childNodes');
      form.appendChild(clobber);

      var wrapper = document.createElement('div');
      wrapper.appendChild(form);

      DOMPurify.sanitize(wrapper, { IN_PLACE: true });

      assert.equal(
        wrapper.querySelectorAll('form').length,
        0,
        'form clobbered by <select name="childNodes"> must be removed'
      );
    }
  );

  QUnit.test(
    'CVE-2026-49459: form clobbered by name="nodeType" is removed so it cannot reset the nesting depth',
    function (assert) {
      if (!formClobbers('nodeType')) {
        assert.ok(true, 'SKIP: no form clobbering in this engine');
        return;
      }

      var repeat = function (str, times) {
        return new Array(times + 1).join(str);
      };

      // A form whose nodeType reads as its <input name="nodeType"> child
      // skips the element depth bookkeeping, restarting the count for
      // everything nested inside it.
      var clean = DOMPurify.sanitize(
        '<div><form><input name="nodeType">' +
          repeat('<div>', 300) +
          '<img src=x onerror=alert(1)>' +
          repeat('</div>', 300) +
          '</form></div>'
      );
      assert.equal(clean, '<div></div>', 'nodeType-clobbered form is removed');

      var wrapper = document.createElement('div');
      var form = document.createElement('form');
      var clobber = document.createElement('input');
      clobber.setAttribute('name', 'nodeType');
      form.appendChild(clobber);
      wrapper.appendChild(form);

      DOMPurify.sanitize(wrapper, { IN_PLACE: true });

      assert.equal(
        wrapper.querySelectorAll('form').length,
        0,
        'nodeType-clobbered form is removed in IN_PLACE mode'
      );
    }
  );

  // ---------------------------------------------------------------------------
  // CVE-2026-49458 (GHSA-hpcv-96wg-7vj8) - nodes from another window/realm.
  // Security decisions keyed on `instanceof X` against this window's
  // constructors short-circuit for foreign-realm nodes. Real iframes cannot
  // reproduce this here (instanceof works across realms in jsdom and
  // Firefox), so the DOMPurify instance below is built from a window whose
  // constructors are not on the prototype chain of this document's nodes,
  // exactly like the constructors of another realm, while the prototype
  // getters stay the real ones.
  // ---------------------------------------------------------------------------

  var createForeignRealmPurify = function (NodeOverride) {
    var foreign = function (Real) {
      var Ctor = function () {};
      Ctor.prototype = Object.create(Real ? Real.prototype : Object.prototype);
      return Ctor;
    };

    return DOMPurify({
      document: document,
      DocumentFragment: foreign(window.DocumentFragment),
      HTMLTemplateElement: window.HTMLTemplateElement,
      Node: NodeOverride || foreign(window.Node),
      NodeFilter: window.NodeFilter,
      NamedNodeMap: foreign(window.NamedNodeMap || window.MozNamedAttrMap),
      Element: foreign(window.Element),
      Text: foreign(window.Text),
      Comment: foreign(window.Comment),
      DOMParser: window.DOMParser,
    });
  };

  QUnit.test(
    'CVE-2026-49458: foreign-realm IN_PLACE root is sanitized, not skipped as clobbered',
    function (assert) {
      var realmPurify = createForeignRealmPurify();

      // Pre-fix `elm.attributes instanceof NamedNodeMap` was false for the
      // foreign NamedNodeMap, so every element - the root included - looked
      // clobbered. The parent-less root can't be removed, so its handlers
      // survived uninspected.
      var root = document.createElement('div');
      root.setAttribute('onmouseover', 'alert(1)');
      root.innerHTML = 'text<b onclick="alert(2)">bold</b>';

      var clean = realmPurify.sanitize(root, { IN_PLACE: true });

      assert.equal(clean, root, 'the input node is returned');
      assert.equal(
        root.getAttribute('onmouseover'),
        null,
        'onmouseover on the foreign-realm root must be stripped'
      );
      assert.equal(
        root.innerHTML,
        'text<b>bold</b>',
        'children are sanitized, not dropped as clobbered'
      );
    }
  );

  QUnit.test(
    'CVE-2026-49458: foreign-realm clobbered form root throws on IN_PLACE',
    function (assert) {
      if (!formClobbers('attributes')) {
        assert.ok(true, 'SKIP: no form clobbering in this engine');
        return;
      }

      var realmPurify = createForeignRealmPurify();
      var form = document.createElement('form');
      form.setAttribute('onmouseover', 'alert(1)');
      var clobber = document.createElement('input');
      clobber.setAttribute('name', 'attributes');
      form.appendChild(clobber);

      assert.throws(
        function () {
          realmPurify.sanitize(form, { IN_PLACE: true });
        },
        /root node is clobbered/,
        'foreign-realm clobbered form must throw on IN_PLACE'
      );
    }
  );

  QUnit.test(
    'CVE-2026-49458: foreign-realm <template>.content is walked and sanitized',
    function (assert) {
      var realmPurify = createForeignRealmPurify();

      // Pre-fix `content instanceof DocumentFragment` was false for the
      // foreign fragment, so the template body was never walked.
      assert.equal(
        realmPurify.sanitize(
          '<b onclick=alert(1)>a</b><template><img src=x onerror=alert(2)></template>'
        ),
        '<b>a</b><template><img src="x"></template>',
        'string input: template content is sanitized'
      );

      var wrapper = document.createElement('div');
      wrapper.innerHTML =
        '<template><img src="x" onerror="alert(3)"></template>';
      var tpl = wrapper.firstChild;
      if (!tpl.content) {
        assert.ok(true, 'SKIP: no <template>.content in this engine');
        return;
      }

      if (!tpl.content.firstChild) {
        // The innerHTML setter does not target the template contents in
        // this engine, build them through the inert contents document
        while (tpl.firstChild) {
          tpl.removeChild(tpl.firstChild);
        }

        var inertImg = tpl.content.ownerDocument.createElement('img');
        inertImg.setAttribute('src', 'x');
        inertImg.setAttribute('onerror', 'alert(3)');
        tpl.content.appendChild(inertImg);
      }

      realmPurify.sanitize(wrapper, { IN_PLACE: true });

      assert.equal(tpl.parentNode, wrapper, 'template is kept');
      var img = tpl.content.firstChild;
      assert.ok(img && img.nodeName === 'IMG', 'template content was reached');
      assert.equal(
        img && img.getAttribute('onerror'),
        null,
        'onerror inside foreign-realm <template> must be stripped'
      );
    }
  );

  QUnit.test(
    'CVE-2026-49458: cross-window node is not mistaken for a string in IN_PLACE mode (GHSA-4w3q-35jp-p934)',
    function (assert) {
      // Where `Node` is an object (older WebKit), _isNode relied on
      // instanceof alone. A node from another window failed it, was
      // stringified to "[object HTMLDivElement]", IN_PLACE was switched off
      // and the node itself was never sanitized.
      if (typeof Symbol === 'undefined' || !Symbol.hasInstance) {
        assert.ok(true, 'SKIP: Symbol.hasInstance not available');
        return;
      }

      var NodeObject = { prototype: Object.create(window.Node.prototype) };
      Object.defineProperty(NodeObject, Symbol.hasInstance, {
        value: function () {
          return false;
        },
      });
      var realmPurify = createForeignRealmPurify(NodeObject);

      var root = document.createElement('div');
      root.setAttribute('onmouseover', 'alert(1)');
      root.innerHTML =
        '<img src="x" onerror="alert(2)"><script>alert(3)</script>';

      var clean = realmPurify.sanitize(root, { IN_PLACE: true });

      assert.equal(clean, root, 'the input node is returned, not a string');
      assert.equal(
        root.getAttribute('onmouseover'),
        null,
        'onmouseover on the cross-window root must be stripped'
      );
      assert.equal(root.innerHTML, '<img src="x">', 'the node is sanitized');
    }
  );

  QUnit.test(
    'CVE-2026-49458: cross-window form root clobbering nodeType or nodeName is refused, not stringified',
    function (assert) {
      // The cross-realm _isNode fallback reads nodeType through the cached
      // getter, so a clobbered form of another realm is still recognized as
      // a node and then refused by the IN_PLACE clobbering pre-flight
      // instead of being stringified and handed back untouched.
      var names = ['nodeType', 'nodeName', 'childNodes', 'attributes'];
      var realmPurify = createForeignRealmPurify();
      for (var i = 0; i < names.length; i++) {
        if (!formClobbers(names[i])) {
          assert.ok(true, 'SKIP: no form clobbering of "' + names[i] + '"');
          continue;
        }

        var form = document.createElement('form');
        form.setAttribute('onmouseover', 'alert(1)');
        var clobber = document.createElement('input');
        clobber.setAttribute('name', names[i]);
        form.appendChild(clobber);

        assert.throws(
          function () {
            realmPurify.sanitize(form, { IN_PLACE: true });
          },
          /root node is clobbered/,
          'cross-window form clobbered by name="' + names[i] + '" must throw'
        );
      }
    }
  );

  QUnit.test(
    'CVE-2026-49459: IN_PLACE root made to look clobbered by a polluted Object.prototype throws instead of keeping its handlers',
    function (assert) {
      // A non-numeric __depth / __removalCount inherited from a polluted
      // Object.prototype makes every element look clobbered. The parent-less
      // root then could not be removed and its attributes were never
      // inspected. The IN_PLACE pre-flight must refuse such a root.
      var pollutions = [
        ['__depth', 'x'],
        ['__removalCount', 'x'],
      ];
      for (var i = 0; i < pollutions.length; i++) {
        var root = document.createElement('a');
        root.setAttribute('href', 'javascript:alert(1)');
        root.setAttribute('onmouseover', 'alert(2)');
        var message = null;
        Object.prototype[pollutions[i][0]] = pollutions[i][1];
        try {
          DOMPurify.sanitize(root, { IN_PLACE: true });
        } catch (error) {
          message = String(error && error.message);
        } finally {
          delete Object.prototype[pollutions[i][0]];
        }

        assert.ok(
          /root node is clobbered/.test(message || ''),
          'Object.prototype.' +
            pollutions[i][0] +
            ': IN_PLACE root must throw, got: ' +
            message +
            ', onmouseover kept: ' +
            root.hasAttribute('onmouseover')
        );
      }
    }
  );

  QUnit.test(
    'CVE-2026-49459: unclobbered IN_PLACE roots are still sanitized (regression guard)',
    function (assert) {
      // A plain form root is not refused by the pre-flight
      var form = document.createElement('form');
      form.setAttribute('onmouseover', 'alert(1)');
      form.setAttribute('action', 'javascript:alert(2)');
      form.appendChild(document.createElement('input'));
      var clean = DOMPurify.sanitize(form, { IN_PLACE: true });
      assert.equal(clean, form, 'the root node itself is returned');
      assert.equal(form.hasAttribute('onmouseover'), false, 'onmouseover removed');
      assert.equal(form.hasAttribute('action'), false, 'javascript: action removed');
      assert.equal(form.querySelectorAll('input').length, 1, 'input is kept');

      // A document fragment root is not an element and is not refused, a
      // clobbered form inside it is removed by the main loop
      var fragment = document.createDocumentFragment();
      var nested = document.createElement('form');
      nested.setAttribute('onmouseover', 'alert(3)');
      var clobber = document.createElement('input');
      clobber.setAttribute('name', 'childNodes');
      nested.appendChild(clobber);
      fragment.appendChild(nested);
      var div = document.createElement('div');
      div.setAttribute('onclick', 'alert(4)');
      fragment.appendChild(div);
      DOMPurify.sanitize(fragment, { IN_PLACE: true });
      if (formClobbers('childNodes')) {
        assert.equal(
          fragment.querySelectorAll('form').length,
          0,
          'clobbered form inside a fragment root is removed'
        );
      } else {
        assert.equal(
          nested.hasAttribute('onmouseover'),
          false,
          'onmouseover removed from the form inside a fragment root'
        );
      }

      assert.equal(
        div.hasAttribute('onclick'),
        false,
        'onclick removed from the element inside a fragment root'
      );
    }
  );

  /* CVE-2026-49978: an attached shadow root nested inside <template>.content
     was reached by no walk. The NodeIterator does not enter shadow trees and
     the template content recursion never inspected shadowRoot, so the payload
     of such a shadow root survived IN_PLACE sanitization and went live once
     the content was stamped into the document (clonable shadow roots are
     copied by cloneNode / importNode). _sanitizeShadowDOM now walks the shadow
     root of every element it iterates. The trees are built inside the inert
     template content, so no image request is made. Engines without
     attachShadow (e.g. jsdom) skip these tests. */
  var supportsShadowRoots = function () {
    var probe = document.createElement('div');
    try {
      probe.attachShadow({ mode: 'open' });
      return true;
    } catch (_) {
      return false;
    }
  };
  var supportsClonableShadowRoots = function () {
    var probe = document.createElement('div');
    try {
      probe.attachShadow({ mode: 'open', clonable: true });
    } catch (_) {
      return false;
    }

    /* Engines predating clonable shadow roots accept the unknown dictionary
       member, but do not copy the shadow root when cloning the host */
    return Boolean(probe.cloneNode(true).shadowRoot);
  };
  QUnit.test(
    'CVE-2026-49978: shadow root inside template.content is sanitized in-place',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        var tpl = document.createElement('template');
        var host = document.createElement('div');
        tpl.content.appendChild(host);
        host.attachShadow({ mode: 'open' }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(tpl, { IN_PLACE: true });

        // The shadow root's onerror attribute must be stripped.
        var shadowImg =
          tpl.content.firstChild &&
          tpl.content.firstChild.shadowRoot &&
          tpl.content.firstChild.shadowRoot.querySelector('img');
        if (shadowImg) {
          assert.equal(
            shadowImg.getAttribute('onerror'),
            null,
            'onerror inside shadow root inside template.content must be stripped'
          );
        } else {
          // The whole img may have been removed; also acceptable.
          assert.ok(
            true,
            '<img> removed entirely from shadow root inside template.content'
          );
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: clonable shadow root inside template.content does not survive stamping',
    function (assert) {
      if (!supportsClonableShadowRoots()) {
        assert.ok(true, 'SKIP: clonable shadow roots not supported in this engine');
        return;
      }

      withFreshPurify(function (purify) {
        var tpl = document.createElement('template');
        var host = document.createElement('div');
        tpl.content.appendChild(host);
        host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(tpl, { IN_PLACE: true });

        // The realistic exploitation path: clone the (now-sanitized)
        // template content into the live document. The cloned shadow
        // tree must not carry the onerror.
        var clone = tpl.content.cloneNode(true);
        var clonedImg =
          clone.firstChild &&
          clone.firstChild.shadowRoot &&
          clone.firstChild.shadowRoot.querySelector('img');
        if (clonedImg) {
          assert.equal(
            clonedImg.getAttribute('onerror'),
            null,
            'onerror inside cloned-stamped shadow root must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely after stamping');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: nested templates: outer.content > inner.content > shadow root',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // Two <template> elements nested by content. The innermost
        // host inside the inner template's content carries the
        // malicious shadow root. Reaches the host only via repeated
        // recursion into template.content.
        var outer = document.createElement('template');
        var inner = document.createElement('template');
        var host = document.createElement('div');
        inner.content.appendChild(host);
        outer.content.appendChild(inner);
        host.attachShadow({ mode: 'open' }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(outer, { IN_PLACE: true });

        var sr =
          outer.content.firstChild &&
          outer.content.firstChild.content &&
          outer.content.firstChild.content.firstChild &&
          outer.content.firstChild.content.firstChild.shadowRoot;
        var img = sr && sr.querySelector('img');
        if (img) {
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror in shadow root inside nested template content must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: wrapper element > template > shadow root: walked via descent',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // A regular <div> as the IN_PLACE root, containing a template,
        // whose content holds a shadow host. The walk must descend
        // through the wrapper, find the template, recurse into
        // template.content, and walk the host's shadow root.
        var root = document.createElement('div');
        var tpl = document.createElement('template');
        var host = document.createElement('div');
        tpl.content.appendChild(host);
        root.appendChild(tpl);
        host.attachShadow({ mode: 'open' }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(root, { IN_PLACE: true });

        var sr =
          root.firstChild &&
          root.firstChild.content &&
          root.firstChild.content.firstChild &&
          root.firstChild.content.firstChild.shadowRoot;
        var img = sr && sr.querySelector('img');
        if (img) {
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror in shadow root inside template inside wrapper must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: <template> nested inside a shadow root inside template.content is walked',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // template.content > host > shadow root > template > img. The
        // walk alternates between shadow-root descent and
        // template-content recursion.
        var outer = document.createElement('template');
        var host = document.createElement('div');
        outer.content.appendChild(host);
        var sr = host.attachShadow({ mode: 'open' });
        var inner = document.createElement('template');
        inner.innerHTML = '<img src=x onerror=alert(1)>';
        sr.appendChild(inner);

        purify.sanitize(outer, { IN_PLACE: true });

        var innerTpl =
          outer.content.firstChild &&
          outer.content.firstChild.shadowRoot &&
          outer.content.firstChild.shadowRoot.querySelector('template');
        var img = innerTpl && innerTpl.content.querySelector('img');
        if (img) {
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror inside <template>.content inside shadow root must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: template.content > shadow root > template > shadow root: alternating descent',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // Outer host with shadow root inside template content, whose
        // shadow contains a <template>, whose content contains an inner
        // host with its own shadow root carrying the payload.
        var tpl = document.createElement('template');
        var outerHost = document.createElement('div');
        tpl.content.appendChild(outerHost);
        var outerSr = outerHost.attachShadow({ mode: 'open' });
        var innerTpl = document.createElement('template');
        outerSr.appendChild(innerTpl);
        var innerHost = document.createElement('div');
        innerTpl.content.appendChild(innerHost);
        innerHost.attachShadow({ mode: 'open' }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(tpl, { IN_PLACE: true });

        var outerShadow =
          tpl.content.firstChild && tpl.content.firstChild.shadowRoot;
        var innerSr =
          outerShadow &&
          outerShadow.firstChild &&
          outerShadow.firstChild.content &&
          outerShadow.firstChild.content.firstChild &&
          outerShadow.firstChild.content.firstChild.shadowRoot;
        var img = innerSr && innerSr.querySelector('img');
        if (img) {
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror in deep shadow > template > shadow chain must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: shadow root nested inside a shadow root inside template.content is walked',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // template.content > host > shadow root > host > shadow root
        var tpl = document.createElement('template');
        var outerHost = document.createElement('div');
        tpl.content.appendChild(outerHost);
        var outerSr = outerHost.attachShadow({ mode: 'open' });
        outerSr.innerHTML = '<b>ok</b><span></span>';
        outerSr.lastChild.attachShadow({ mode: 'open' }).innerHTML =
          '<p>ok</p><img src=x onerror=alert(1)><script>alert(2)</script>';

        purify.sanitize(tpl, { IN_PLACE: true });

        var shadow = tpl.content.firstChild.shadowRoot;
        assert.equal(
          shadow.innerHTML,
          '<b>ok</b><span></span>',
          'benign content of the outer shadow root is kept'
        );
        assert.equal(
          shadow.lastChild.shadowRoot.innerHTML,
          '<p>ok</p><img src="x">',
          'payload of the inner shadow root is sanitized'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: clonable shadow root in nested template survives stamping unscathed',
    function (assert) {
      if (!supportsClonableShadowRoots()) {
        assert.ok(true, 'SKIP: clonable shadow roots not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // End-to-end version of the deeper-nesting case: clonable
        // shadow root inside nested template content, then stamp the
        // outer template into the live document. The cloned tree
        // must not carry the original onerror.
        var outer = document.createElement('template');
        var inner = document.createElement('template');
        var host = document.createElement('div');
        inner.content.appendChild(host);
        outer.content.appendChild(inner);
        host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(outer, { IN_PLACE: true });

        // Stamp the outer template into the live document.
        var stamped = outer.content.cloneNode(true);
        var stampedSr =
          stamped.firstChild &&
          stamped.firstChild.content &&
          stamped.firstChild.content.firstChild &&
          stamped.firstChild.content.firstChild.shadowRoot;
        var stampedImg = stampedSr && stampedSr.querySelector('img');
        if (stampedImg) {
          assert.equal(
            stampedImg.getAttribute('onerror'),
            null,
            'stamped img onerror stripped after deep-nested sanitize'
          );
        } else {
          assert.ok(true, '<img> removed entirely after stamping');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: clonable shadow root inside template.content of a node input is sanitized',
    function (assert) {
      if (!supportsClonableShadowRoots()) {
        assert.ok(true, 'SKIP: clonable shadow roots not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // Without IN_PLACE the node is imported (cloned) into the
        // sanitization document, which copies the clonable shadow root.
        var root = document.createElement('div');
        var tpl = document.createElement('template');
        var host = document.createElement('div');
        tpl.content.appendChild(host);
        root.appendChild(tpl);
        host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
          '<img src=x onerror=alert(1)>';

        var clean = purify.sanitize(root, { RETURN_DOM: true });

        var cleanTpl = clean.querySelector('template');
        var sr =
          cleanTpl &&
          cleanTpl.content.firstChild &&
          cleanTpl.content.firstChild.shadowRoot;
        var img = sr && sr.querySelector('img');
        if (img) {
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror in the copied shadow root must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely');
        }
      });
    }
  );

  /* CVE-2026-65901 (GHSA-x4vx-rjvf-j5p4): a live node handed in with
     IN_PLACE can define an own nodeName. The allow/forbid decisions trusted
     that instance-visible property, so a real <script> claiming to be a
     "DIV" was kept and ran once the sanitized tree was inserted into the
     document, and an <a> claiming to be an "IMG" kept a data: URI. The name
     is now read through the cached Node.prototype getter, and a node whose
     own nodeName diverges from it is removed like any other clobbered node. */
  var X4VX_DATA_URI =
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==';
  var spoofNodeName = function (node, name) {
    Object.defineProperty(node, 'nodeName', {
      value: name,
      configurable: true,
    });
    return node;
  };
  var hasDataHref = function (node) {
    return /^\s*data:/i.test(node.getAttribute('href') || '');
  };
  QUnit.test(
    'CVE-2026-65901: IN_PLACE removes a <script> child spoofing nodeName as DIV',
    function (assert) {
      withFreshPurify(function (purify) {
        var host = document.createElement('div');
        var benign = document.createElement('p');
        benign.appendChild(document.createTextNode('ok'));
        host.appendChild(benign);
        var script = document.createElement('script');
        script.textContent = 'window.__x4vx_script = 1';
        host.appendChild(spoofNodeName(script, 'DIV'));

        var clean = purify.sanitize(host, { IN_PLACE: true });

        assert.strictEqual(clean, host, 'the root node itself is returned');
        assert.notEqual(
          script.parentNode,
          host,
          '<script> spoofing nodeName as DIV is removed'
        );
        assert.equal(host.childNodes.length, 1, 'only the benign child is left');
        assert.strictEqual(host.firstChild, benign, 'benign <p> is kept');
      });
    }
  );
  QUnit.test(
    'CVE-2026-65901: IN_PLACE does not keep a data: href on an <a> spoofing nodeName as IMG',
    function (assert) {
      withFreshPurify(function (purify) {
        var host = document.createElement('div');
        var link = document.createElement('a');
        link.setAttribute('href', X4VX_DATA_URI);
        link.appendChild(document.createTextNode('click'));
        host.appendChild(spoofNodeName(link, 'IMG'));

        purify.sanitize(host, { IN_PLACE: true });

        assert.ok(
          link.parentNode !== host || !hasDataHref(link),
          '<a> spoofing nodeName as IMG is removed or loses its data: href'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65901: a nodeName getter switching to IMG after the first reads can not keep a data: href',
    function (assert) {
      withFreshPurify(function (purify) {
        var host = document.createElement('div');
        var link = document.createElement('a');
        link.setAttribute('href', X4VX_DATA_URI);
        link.appendChild(document.createTextNode('click'));
        host.appendChild(link);
        /* Consistent while the node is checked for clobbering and its tag
           name is looked up, spoofed for the attribute checks after */
        var reads = 0;
        Object.defineProperty(link, 'nodeName', {
          get: function () {
            reads++;
            return reads <= 2 ? 'A' : 'IMG';
          },
          configurable: true,
        });

        purify.sanitize(host, { IN_PLACE: true });

        assert.ok(
          link.parentNode !== host || !hasDataHref(link),
          'data: href is not kept by a nodeName that turns into IMG'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65901: IN_PLACE root spoofing nodeName is refused',
    function (assert) {
      withFreshPurify(function (purify) {
        var root = document.createElement('script');
        root.textContent = 'window.__x4vx_root = 1';
        spoofNodeName(root, 'DIV');

        var message = null;
        try {
          purify.sanitize(root, { IN_PLACE: true });
        } catch (error) {
          message = String(error && error.message);
        }

        assert.ok(
          message !== null && /clobbered/.test(message),
          'spoofed IN_PLACE root must throw, got: ' + message
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65901: IN_PLACE removes an adopted <script> spoofing nodeName as DIV',
    function (assert) {
      if (
        !document.implementation ||
        typeof document.implementation.createHTMLDocument !== 'function' ||
        typeof document.adoptNode !== 'function'
      ) {
        assert.ok(true, 'SKIP: no createHTMLDocument / adoptNode');
        return;
      }

      withFreshPurify(function (purify) {
        /* Build the hostile subtree in another document, then adopt it into
           this one before sanitizing it in place */
        var source = document.implementation.createHTMLDocument('');
        var host = source.createElement('div');
        var script = source.createElement('script');
        script.textContent = 'window.__x4vx_adopted = 1';
        host.appendChild(spoofNodeName(script, 'DIV'));
        var link = source.createElement('a');
        link.setAttribute('href', X4VX_DATA_URI);
        host.appendChild(spoofNodeName(link, 'IMG'));
        host = document.adoptNode(host);

        purify.sanitize(host, { IN_PLACE: true });

        assert.notEqual(
          script.parentNode,
          host,
          'adopted <script> spoofing nodeName as DIV is removed'
        );
        assert.ok(
          link.parentNode !== host || !hasDataHref(link),
          'adopted <a> spoofing nodeName as IMG keeps no data: href'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65901: IN_PLACE removes a foreign-realm <script> spoofing nodeName as DIV',
    function (assert) {
      var realmPurify = createForeignRealmPurify();
      var host = document.createElement('div');
      var script = document.createElement('script');
      script.textContent = 'window.__x4vx_foreign = 1';
      host.appendChild(spoofNodeName(script, 'DIV'));
      var link = document.createElement('a');
      link.setAttribute('href', X4VX_DATA_URI);
      host.appendChild(spoofNodeName(link, 'IMG'));

      realmPurify.sanitize(host, { IN_PLACE: true });

      assert.notEqual(
        script.parentNode,
        host,
        'foreign realm: <script> spoofing nodeName as DIV is removed'
      );
      assert.ok(
        link.parentNode !== host || !hasDataHref(link),
        'foreign realm: <a> spoofing nodeName as IMG keeps no data: href'
      );
    }
  );
};
