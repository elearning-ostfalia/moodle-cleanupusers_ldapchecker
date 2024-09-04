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
 * Sub-plugin ldapchecker.
 *
 * @package   userstatus_ldapchecker
 * @copyright 2016/17 N. Herrmann
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace userstatus_ldapchecker;

use core\session\exception;
use tool_cleanupusers\archiveduser;
use tool_cleanupusers\userstatusinterface;



defined('MOODLE_INTERNAL') || die;

/**
 * Class that checks the status of different users depending on the time they have not signed in for.
 *
 * @package    userstatus_ldapchecker
 * @copyright  2016/17 N Herrmann
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

class ldapchecker implements userstatusinterface {

    /** @var int seconds until a user should be deleted */
    private $timedelete;

    /** @var array lookuptable for ldap users */
    private $lookup = array();

    private $config;

    /**
     * This constructor sets timesuspend and timedelete from days to seconds.
     * @throws \dml_exception
     */
    public function __construct($testing = false) {

        $this->config = get_config('userstatus_ldapchecker');

        // Calculates days to seconds.
        $this->timedelete = $this->config->deletetime * 86400;

        // Only connect to LDAP if we are not in testing case
        if ($testing === false) {

            $ldap = ldap_connect($this->config->host_url) or die("Could not connect to $this->config->host_url");

            $bind = ldap_bind($ldap, $this->config->bind_dn, $this->config->bind_pw); // returns 1 if correct

            if($bind) {
                $this->log("ldap_bind successful");

                $contexts = $this->config->contexts;

                $uid = $this->config->ldap_username_attribute;
                $attributes = [$uid];
                $filter = $this->config->search_filter; // '(cn=*)';
                $search = ldap_search($ldap, $contexts, $filter, $attributes) or die("Error in search Query: " . ldap_error($ldap));
                $result = ldap_get_entries($ldap, $search);

                foreach ($result as $user) {
                    if(isset($user[$uid])) {
                        foreach ($user[$uid] as $cn) {
                            $this->lookup[$cn] = true;
                        }
                    }
                }

                $this->log("ldap server sent " . count($this->lookup) . " users");

            } else {
                $this->log("ldap_bind failed");
                // fatal error!
                throw new exception("cannot connect to LDAP server");
            }
        }

    }

    private function log($text) {
        file_put_contents($this->config->log_folder . "/debug_log_ldapchecker.log",
            "\n[".date("d-M-Y - H:i ")."] $text " , FILE_APPEND);
    }

    /**
     * All users who are not suspended and not deleted are selected. If a user did not sign in for the hitherto
     * determined suspendtime he/she will be returned.
     * Users not signed in for the hitherto determined suspendtime, do not show up in the ldap lookuptable.
     * The array includes merely the necessary information which comprises the userid, lastaccess, suspended, deleted
     * and the username.
     *
     * @return array of users to suspend
     * @throws \dml_exception
     */
    public function get_to_suspend() {
        global $DB;
        if (count($this->lookup) == 0) {
            $this->log("no users from LDAP found => do not evaluate users to suspend");
            return [];
        }

        $select = "auth='" . $this->config->auth_method . "' AND deleted=0 AND suspended=0";
        $this->log("[get_to_suspend] " . $select);
        $users = $DB->get_records_select('user', $select, null, '',
            "id, suspended, lastaccess, username, deleted");
        $this->log("[get_to_suspend] found " . count($users) . " users in user table to check");


        $tosuspend = [];

        foreach ($users as $key => $user) {
            $this->log("[get_to_suspend] user " . $user->username);
            if (!is_siteadmin($user) && !array_key_exists($user->username, $this->lookup)) {
                $suspenduser = new archiveduser(
                    $user->id,
                    $user->suspended,
                    $user->lastaccess,
                    $user->username,
                    $user->deleted);
                $tosuspend[$key] = $suspenduser;
                $this->log("[get_to_suspend] " . $user->username . " marked");
            }
        }
        $this->log("[get_to_suspend] marked " . count($tosuspend) . " users");

        return $tosuspend;
    }

    /**
     * All users who never logged in will be returned in the array.
     * The array includes merely the necessary information which comprises the userid, lastaccess, suspended, deleted
     * and the username.
     *
     * @return array of users who never logged in
     * @throws \dml_exception
     */
    public function get_never_logged_in() {
        global $DB;
        $select = "auth='" . $this->config->auth_method . "' AND lastaccess=0 AND deleted=0 AND firstname!='Anonym'";
        $arrayofuser = $DB->get_records_select('user', $select);
        $neverloggedin = array();
        foreach ($arrayofuser as $key => $user) {
            if (empty($user->lastaccess) && $user->deleted == 0) {
                $informationuser = new archiveduser(
                    $user->id,
                    $user->suspended,
                    $user->lastaccess,
                    $user->username,
                    $user->deleted);
                $neverloggedin[$key] = $informationuser;
            }
        }

        return $neverloggedin;
    }

    /**
     * All users who should be deleted will be returned in the array.
     * The array includes merely the necessary information which comprises the userid, lastaccess, suspended, deleted
     * and the username.
     * The function checks the user table and the tool_cleanupusers_archive table. Therefore, users who are suspended by
     * the tool_cleanupusers plugin and users who are suspended manually are screened.
     *
     * @return array of users who should be deleted.
     * @throws \dml_exception
     */
    public function get_to_delete() {
        global $DB;

        // Select clause for users who are suspended.
        $select = "auth='" . $this->config->auth_method . "' AND deleted=0 AND suspended=1 AND (lastaccess!=0 OR firstname='Anonym')";
        $users = $DB->get_records_select('user', $select);
        $todelete = array();

        foreach ($users as $key => $user) {
            if (!is_siteadmin($user)) {
                $mytimestamp = time();
                // User was suspended by the plugin.
                if ($DB->record_exists('tool_cleanupusers', array('id' => $user->id))) {
                    $tableuser = $DB->get_record('tool_cleanupusers', array('id' => $user->id));
                    $timearchived = $tableuser->timestamp;
                    $timenotloggedin = $mytimestamp - $timearchived;
                    // When the user did not sign in for the timedeleted he/she should be deleted.
                    if ($timenotloggedin > $this->timedelete) {
                        if ($DB->record_exists('tool_cleanupusers_archive', array('id' => $user->id))) {
                            $shadowtableuser = $DB->get_record('tool_cleanupusers_archive', array('id' => $user->id));
                            $informationuser = new archiveduser($shadowtableuser->id, $shadowtableuser->suspended,
                                $shadowtableuser->lastaccess, $shadowtableuser->username, $shadowtableuser->deleted);
                            $todelete[$key] = $informationuser;
                            $this->log("[get_to_delete] "
                                . $shadowtableuser->username . " / " . $user->username . " (suspended by plugin) marked");
                        } else {
                            $this->log("[get_to_delete] "
                                . $user->username . " (suspended by plugin) has no entry in archive, skipping");
                        }
                    }
                }
            }
        }
        $this->log("[get_to_delete] marked " . count($todelete) . " users");

        return $todelete;
    }

    /**
     * All users that should be reactivated will be returned.
     *
     * @return array of objects
     * @throws \dml_exception
     * @throws \dml_exception
     */
    public function get_to_reactivate() {
        global $DB;
        if (count($this->lookup) == 0) {
            $this->log("no users from LDAP found => do not evaluate users to reactivate");
            return [];
        }

        // Only users who are currently suspended are relevant.
        $select = "auth='" . $this->config->auth_method . "' AND deleted=0 AND suspended=1";
        $users = $DB->get_records_select('user', $select);
        $toactivate = array();

        // $config = get_config('userstatus_ldapchecker');

        foreach ($users as $key => $user) {
            if (!is_siteadmin($user)) {
                // User was suspended by the plugin.
                if ($DB->record_exists('tool_cleanupusers', array('id' => $user->id))) {
                    if ($DB->record_exists('tool_cleanupusers_archive', array('id' => $user->id))) {
                        $shadowuser = $DB->get_record('tool_cleanupusers_archive', array('id' => $user->id));
                        if (!$DB->record_exists('user', array('username' => $shadowuser->username))) {
//                            if (!$config->reactivate_only_found || array_key_exists($shadowuser->username, $this->lookup)) {
                            if (array_key_exists($shadowuser->username, $this->lookup)) {
                                // Es werden nur Nutzer zurückgeholt werden, die auch im LDAP
                                // gefunden werden.
                                $activateuser = new archiveduser($shadowuser->id, $shadowuser->suspended, $shadowuser->lastaccess,
                                    $shadowuser->username, $shadowuser->deleted);
                                $toactivate[$key] = $activateuser;
                                $this->log("[get_to_reactivate] "
                                    .$shadowuser->username . " / " . $user->username . " (suspended by plugin) marked");
                            }
                        } else {
                            $this->log("[get_to_reactivate] "
                                . $user->username . " (suspended by plugin) already in user table, skipping");
                        }
                    } else {
                        $this->log("[get_to_reactivate] "
                            . $user->username . " (suspended by plugin) has no entry in archive, skipping");
                    }
                }
            }
        }
        $this->log("[get_to_reactivate] marked " . count($toactivate) . " users");

        return $toactivate;
    }

    public function fill_ldap_response_for_testing($dummy_ldap) {
        $this->lookup = $dummy_ldap;
    }

}
