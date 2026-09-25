/* MK Security Shield v2.0 — Admin JS */
/* global mkssAdmin, jQuery */

(function ($) {
	'use strict';

	// ── Tab navigation ──────────────────────────────────────
	$(document).on('click', '.mkss-tab-btn', function () {
		var target = $(this).data('tab');
		$('.mkss-tab-btn').removeClass('active');
		$('.mkss-tab-panel').removeClass('active');
		$(this).addClass('active');
		$('#mkss-tab-' + target).addClass('active');
	});

	// Restore active tab from URL hash or sessionStorage
	var hash = window.location.hash.replace('#', '') || sessionStorage.getItem('mkss_tab') || 'dashboard';
	var $btn = $('.mkss-tab-btn[data-tab="' + hash + '"]');
	if ($btn.length) {
		$btn.trigger('click');
	} else {
		$('.mkss-tab-btn').first().trigger('click');
	}

	$(document).on('click', '.mkss-tab-btn', function () {
		sessionStorage.setItem('mkss_tab', $(this).data('tab'));
	});

	// ── AJAX save ───────────────────────────────────────────
	$(document).on('click', '#mkss-save-btn', function () {
		var $btn    = $(this);
		var $notice = $('#mkss-save-notice');

		$btn.prop('disabled', true).text('Saving…');
		$notice.hide();

		var data = { action: 'mkss_save_settings', nonce: mkssAdmin.nonce };

		// Gather all form inputs
		$('.mkss-wrap input, .mkss-wrap select, .mkss-wrap textarea').each(function () {
			var name = $(this).attr('name');
			if (!name) return;
			if ($(this).is(':checkbox')) {
				data[name] = $(this).is(':checked') ? '1' : '0';
			} else {
				data[name] = $(this).val();
			}
		});

		$.post(mkssAdmin.ajaxUrl, data, function (response) {
			$btn.prop('disabled', false).text('Save Settings');
			if (response.success) {
				$notice.text('✓ Settings saved.').show().delay(3000).fadeOut();
			} else {
				$notice.css({ background: '#f8d7da', color: '#721c24', borderColor: '#f5c6cb' })
					.text('Error: ' + (response.data || 'Could not save.')).show();
			}
		}).fail(function () {
			$btn.prop('disabled', false).text('Save Settings');
			$notice.css({ background: '#f8d7da', color: '#721c24', borderColor: '#f5c6cb' })
				.text('Network error. Please try again.').show();
		});
	});

	// ── File integrity scan ─────────────────────────────────
	$(document).on('click', '#mkss-run-scan', function () {
		var $btn    = $(this);
		var $result = $('#mkss-scan-result');

		$btn.prop('disabled', true).text('Scanning…');
		$result.hide().removeClass('success error');

		$.post(mkssAdmin.ajaxUrl, {
			action: 'mkss_file_integrity',
			nonce:  mkssAdmin.nonce
		}, function (response) {
			$btn.prop('disabled', false).text('Run File Integrity Scan Now');
			if (response.success && response.data) {
				var d = response.data;
				var msg = d.ok
					? '✓ All clear — ' + d.checked + ' files checked, ' + d.skipped + ' intentionally skipped.'
					: '⚠ Issues found in ' + (d.issues ? d.issues.length : 0) + ' file(s). An alert has been sent.';
				$result.addClass(d.ok ? 'success' : 'error').text(msg).show();
			} else {
				$result.addClass('error').text('Scan failed. Check error log.').show();
			}
		}).fail(function () {
			$btn.prop('disabled', false).text('Run File Integrity Scan Now');
			$result.addClass('error').text('Network error during scan.').show();
		});
	});

	// ── Severity filter ─────────────────────────────────────
	$(document).on('click', '.mkss-log-filters a', function (e) {
		e.preventDefault();
		$('.mkss-log-filters a').removeClass('active');
		$(this).addClass('active');
		var sev = $(this).data('sev');
		$('.mkss-log-table tbody tr').each(function () {
			if (sev === 'all') {
				$(this).show();
			} else {
				$(this).toggle($(this).data('sev') == sev);
			}
		});
	});

})(jQuery);
