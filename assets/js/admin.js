/* global mkssData, jQuery */
(function ($) {
	'use strict';
	$(document).on('click', '.mkss-save-btn', function () {
		var $button = $(this);
		var $form = $button.closest('.mkss-settings-form');
		var $notice = $form.find('.mkss-save-msg');
		var settings = {};
		$form.find('input[name], select[name], textarea[name]').each(function () {
			settings[this.name] = $(this).is(':checkbox') ? (this.checked ? '1' : '0') : $(this).val();
		});
		$button.prop('disabled', true);
		$notice.hide();
		$.post(mkssData.ajaxUrl, {action: 'mkss_save_settings', nonce: mkssData.nonce, settings: settings})
			.done(function (response) {
				$notice.css('color', response.success ? 'green' : '#b32d2e')
					.text(response.success ? mkssData.savedText : mkssData.errorText).show();
			})
			.fail(function () { $notice.css('color', '#b32d2e').text(mkssData.errorText).show(); })
			.always(function () { $button.prop('disabled', false); });
	});
})(jQuery);
