<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * MIME Scanner antivirus - Allow only specified MIME files to be uploaded to Moodle.
 *
 * @package    antivirus_mimescanner
 * @copyright  2018 SQLearn
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_mimescanner;

use core\antivirus\scanner_exception;
use core\session\exception;

defined('MOODLE_INTERNAL') || die();

class scanner extends \core\antivirus\scanner{


    public function is_configured(){

        $allowedMimeTypes = trim($this->get_config('allowedmimetypes'));
        return !empty($allowedMimeTypes) ? true : false;
    }


    public function scan_file($file, $filename, $deleteinfected){
        if (!is_readable($file)) {
            // This should not happen.
            debugging('File is not readable.');
            return;
        }

        $allowed = $this->scan_file_using_mime_scanner_tool($file);

        if ($allowed == 1) {
            // No problem found, MIME type is allowed.
            return;
        } else if ($allowed == 0) {
            // Problem found, file MIME type is not allowed.
            unlink($file);
            throw new exception('mimenotallowed','antivirus_mimescanner');

        } else {
            // Unknown problem.
            debugging('Error occurred during file scanning.');
            return;
        }
    }

    /*
     * Check if upload file MIME type is allowed from the plugin settings.
     */
    public function scan_file_using_mime_scanner_tool($file){

        // All specified MIME types that are allowed.
        $allowedMimeTypes = explode("\r\n",$this->get_config('allowedmimetypes'));

        //MIME type of the uploaded file.
        $mime = mime_content_type($file);

        // Returns 0 if MIME type of uploaded file is allowed or 1 if MIME type is not allowed.
        return in_array($mime, $allowedMimeTypes) ? 1 : 0;
    }
}