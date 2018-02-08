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

/*        $isConfigured = trim($this->get_config('allowedmimetypes'));
        return !empty($isConfigured) ? true : false;*/
        return true;
    }


    public function scan_file($file, $filename, $deleteinfected){
        if (!is_readable($file)) {
            // This should not happen.
            debugging('File is not readable.');
            return;
        }

        // Execute the scan using antivirus own scanning tool, we assume it returns 0 if no virus is found, 1 if file is infected, any other number on error.
        $return = $this->scan_file_using_mime_scanner_tool($file);

        if ($return == 0) {
            // Perfect, no problem found, file is clean.
            return;
        } else if ($return == 1) {

            unlink($file);
            throw new exception('mimenotallowed','antivirus_mimescanner');

        } else {
            // Unknown problem.
            debugging('Error occurred during file scanning.');
            return;
        }
    }


    public function scan_file_using_mime_scanner_tool($file){

        $whitelist = explode("\r\n",$this->get_config('allowedmimetypes'));
        $mime = mime_content_type($file);


        if (!in_array($mime, $whitelist)) {
            $return = 1;
        }else{
            $return = 0;
        }
        // Scanning routine using antivirus own tool goes here.
        // ...
        // For example purposes, we assume it returns 0 if no virus is found, 1 if file is infected, any other number on error.
        return $return;
    }
}