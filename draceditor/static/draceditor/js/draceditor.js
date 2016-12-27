(function ($) {
    if (!$) {
        $ = django.jQuery;
    }
    $.fn.draceditor = function() {

    // CSRF code
    var getCookie = function(name) {
        var cookieValue = null;
        var i = 0;
        if (document.cookie && document.cookie !== '') {
            var cookies = document.cookie.split(';');
            for (i; i < cookies.length; i++) {
                var cookie = jQuery.trim(cookies[i]);
                // Does this cookie string begin with the name we want?
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    // Markdown Image Uploader auto insert to textarea.
    // with special insert, eg: ![avatar.png](i.imgur.com/DytfpTz.png)
    var uploadFile = function(selector) {
        $selector.on('change', function(evt) {
          evt.preventDefault();
          var formData = new FormData($('form').get(0));
          formData.append("csrfmiddlewaretoken", getCookie('csrftoken'));

          $.ajax({
              url: dracEditor.data('upload-urls-path'),
              type: 'POST',
              data: formData,
              async: true,
              cache: false,
              contentType: false,
              enctype: 'multipart/form-data',
              processData: false,
              beforeSend: function() {
                  console.log("uploading...");
              },
              success: function (response) {
                  if (response.status == 200) {
                      var name = response.name;
                      var link = response.link;
                      //insertText(textarea_id, "![", "]("+link+")", name);
                  }else {
                      try {
                          var error = JSON.parse(response.error);
                          alert('Vailed to upload! ' + error['data']['error'] + ', error_code: ' + error['status']);
                      }catch(error){
                          alert('Vailed to upload! ' + response.error + ', error_code :' + response.status);
                      }
                      console.log(response);
                  }
              },
              error: function(response) {
                  console.log("error", response);
              }
          });
          return false;
        }
    }

    // Markdown Emoji
    // require `atwho/atwho.min.js` and list `emojis` from `atwho/emojis.min.js`
    var onEmoji = function() {
      $emojis = emojis; // from `atwho/emojis.min.js`
      var emoji_config = {
          at: ":",
          data: $.map($emojis, function(value, i) {return {key: value.replace(/:/g , ''), name:value}}),
          displayTpl: "<li>${name} <img src='"+dracEditor.data('base-emoji-url')+"'${key}.png'  height='20' width='20' /></li>",
          insertTpl: ':${key}:',
          delay: 400
      }
      // Triger process if inserted: https://github.com/ichord/At.js/wiki/Events#insertedatwho
      dracEditor.atwho(emoji_config).on('inserted.atwho', function(event, flag, query) {
        //$('.markdownx').markdownx();
      });
    }

    // Markdown Mention
    var onMention = function() {
      dracEditor.atwho({
        at: "@[",
        displayTpl: "<li>${name}</li>",
        insertTpl: "@[${key}]",
        limit: 20,
        callbacks: {
            remoteFilter: function(query, callback) {
              $.ajax({
                  url: dracEditor.data('search-users-urls-path'),
                  data: {
                      'username': query,
                      'csrfmiddlewaretoken': getCookie('csrftoken')
                  },
                  success: function(data) {
                      if (data['status'] == 200) {
                        var array_data = [];
                        for (var i = 0; i < data['data'].length; i++) {
                            array_data.push(data['data'][i].username)
                        }
                        mapping = $.map(array_data, function(value, i) {return {key: value, name:value}}),
                        callback(mapping);
                      }
                  }
              });
            }//end remoteFilter
        }
      });
    }

    var draceditor = $(this);
    var dracEditor = $(this).find('.draceditor');
    draceditor.trigger('draceditor.init');

    uploadFile($('.upload-image-file');
    onMention();
    onEmoji();
};

$(function() {
    $('.draceditor').draceditor();
});
})(jQuery);
