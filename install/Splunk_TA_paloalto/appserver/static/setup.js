require([
    'jquery',
    "splunkjs/mvc/simplexml/ready!"
], function(
    $
) {

function return_status_banner() {
    return '<div id="info_banner" class="info">Successfully updated configuration for add-on "Splunk_TA_paloalto". </div>' +
    '<div id="save_err_banner" class="error">Fail to update configuration for add-on "Splunk_TA_paloalto". </div>' +
    '<div id="load_err_banner" class="error">Fail to load configuration for add-on "Splunk_TA_paloalto". </div>';
}

function return_page() {
    return '<div class="entityEditForm"><div class="formWrapper">' +
                '<div class="fieldsetWrapper" id="credSettingId">' +
                    '<fieldset>' +
                        '<legend>PAN Device Credentials</legend>' +
                        '<p>These are the credentials that will be used to communicate with your Palo Alto Networks Firewall or Panorama.</p>' +
                        '<div>' +
                            '<a class="color-gray mgr-16 credBtn btn" id="passwordBtnAdd">Add Account</a>' +
                        '</div>' +
                        '<br>' +
                        '<br>' +
                        '<div>' +
                            '<table id="passwordCredTable" class="table mg-10" style="display: table;">' +
                                '<thead class="tableHead">' +
                                    '<tr>' +
                                    '</tr>' +
                                '</thead>' +
                                '<tbody class="tableBody">' +
                                '</tbody>' +
                            '</table>' +
                        '</div>' +
                    '</fieldset>' +
                '</div>' +
                '<div class="fieldsetWrapper" id="wildfire_SettingId">' +
                    '<fieldset>' +
                        '<legend>WildFire Cloud API Key</legend>' +
                        '<p class="helpText"> Used to retrieve reports from the WildFire Cloud.  An API Key is available from the WildFire Portal (<a href="https://wildfire.paloaltonetworks.com" target="_blank">https://wildfire.paloaltonetworks.com</a>).</p>' +
                        '<div class="widget" style="display: block;">' +
                            '<label>WildFire API Key</label>' +
                            '<div>' +
                                '<input class="index_input" type="password" id="wildfire_api_key_id">' +
                            '</div>' +
                            '<div class="widgeterror" style="display: none;">' +
                            '</div>' +
                        '</div>' +
                    '</fieldset>' +
                '</div>' +
                '<div class="fieldsetWrapper" id="AF_SettingId">' +
                    '<fieldset>' +
                        '<legend>AutoFocus API Key</legend>' +
                        '<p class="helpText"> Used to retrieve reports from the AutoFocus Cloud. (<a href="https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_api/get-started-with-the-autofocus-api/get-your-api-key#36712" target="_blank">Get Your API Key</a>).</p>' +
                        '<div class="widget" style="display: block;">' +
                            '<label>AutoFocus API Key</label>' +
                            '<div>' +
                                '<input class="index_input" type="password" id="autofocus_api_key_id">' +
                            '</div>' +
                            '<div class="widgeterror" style="display: none;">' +
                            '</div>' +
                        '</div>' +
                    '</fieldset>' +
                '</div>' +
                '<div class="shadow">' +
                '</div>' +
            '</div> <!-- end of form_wrapper-->' +
            '<div class="dialog passwordCredDialog">' +
                '<div id="passwordCredDialog" class="dialog-header color-gray pd-16">' +
                    'Add Account' +
                '</div>' +
                '<div class="dialog-content pd-16">' +
                    '<form autocomplete="off" id="passwordCredForm" class="credform">' +
                    '</form>' +
                '</div>' +
            '</div>' +
            '<div class="jmFormActions" style="">' +
                    '<button class="my-btn-secondary" type="button"><span>Cancel</span></button>' +
                    '<button type="submit" class="my-btn-primary"><span>Save</span></button>' +
            '</div>' +
        '</div></div>';
}

function return_cred_form() {
        return '<div class="dialog">' +
            '<div class="dialog-header pd-16">' +
                'Add New Credentials' +
            '</div>' +
            '<div class="dialog-content pd-16">' +
                '<form autocomplete="off" id="form">' +
                '</form>' +
            '</div>' +
        '</div>';
}


// begin to process the doc
    var appname = Splunk.util.getCurrentApp();
    // load css
    var cssLinks = [ '/en-US/static/css/view.css', '/en-US/static/css/skins/default/default.css', '/en-US/static/css/print.css', '/en-US/static/css/tipTip.css', '/en-US/static/build/css/splunk-components-enterprise.css', '/en-US/static/css/admin.css'];
    for(var i = 0; i < cssLinks.length; i++) {
        $("<link>").attr({
            rel: "stylesheet",
            type: "text/css",
            href: cssLinks[i],
        }).appendTo("head");
    }
    // remove bootstrap-enterprise.css
    $("head").find("link[type='text/css']").each(function(idx) {
        var ele = $(this);
        if (ele.attr('href').indexOf("css/bootstrap-enterprise.css") > 0) {
            ele.remove();
        }
    });
    // generate the html
    $("body").prepend(return_status_banner());
    $('#setup_page_container').html(return_page());
    $('#info_banner').hide();
    $('#save_err_banner').hide();
    $('#load_err_banner').hide();

    var currentAction = "New";

    function htmlEscape(str) {
        return String(str)
                   .replace(/&/g, '&amp;')
                   .replace(/"/g, '&quot;')
                   .replace(/'/g, '&#39;')
                   .replace(/</g, '&lt;')
                   .replace(/>/g, '&gt;');
    }

    function htmlUnescape(value){
        return String(value)
                   .replace(/&quot;/g, '"')
                   .replace(/&#39;/g, "'")
                   .replace(/&lt;/g, '<')
                   .replace(/&gt;/g, '>')
                   .replace(/&amp;/g, '&');
    }

    function isTrue(value) {
        if (value === undefined) {
            return 0;
        }
        value = value.toUpperCase();
        var trues = ["1", "TRUE", "T", "Y", "YES"];
        return trues.indexOf(value) >= 0;
    }

    function setCheckBox(boxId, value) {
        if (value === undefined) {
            value = "0";
        }
        value = value.toLowerCase();
        if (value == "1" || value == "true" || value == "yes") {
            $("#" + boxId).prop("checked", true);
        } else {
            $("#" + boxId).prop("checked", false);
        }
    };


    function updateGlobalSettings(settings) {
        // Global settings
        if (settings.global_settings === undefined) {
            return;
        }
        $("#log_level_id").val(settings["global_settings"]["log_level"]);

    };

    var passwordColumns = [{
        id: "username",
        name: "Username",
        name_with_desc: "Account Username*",
        required: "required",
        hide: false,
        type: 'text',
        dialogHide: false,
    }, {
        id: "password",
        name: "Password",
        name_with_desc: "Account Password*",
        required: "required",
        hide: true,
        type: 'password',
        dialogHide: false,
    }];

    function updateCredentialSettings(cols, credentialSettings) {
        var creds = [];
        var credsMap = {};
        if (credentialSettings) {
            for (var k in credentialSettings) {
                if (isTrue(credentialSettings[k].removed)) {
                    continue;
                }
                var rec = [k];
                for (var i = 1; i < cols.length; i++) {
                    var val = credentialSettings[k][cols[i].id]
                    if (val === undefined || val == null) {
                        val = "";
                    }
                    rec.push(val);
                }
                creds.push(rec);
                credsMap[k] = rec;
            }
        }
        return {
            "data": creds,
            "dataMap": credsMap,
        };
    };

    var tables = {};
    var dialogs = {};

    function showDialog(dialogId){
        $("." + dialogId).css("display", "block");
        $(".shadow").css("display", "block");
    };

    function hideDialog(dialogId){
        $("." + dialogId).css("display", "none");
        $(".shadow").css("display", "none");
    };

    function hideDialogHandler(e){
        var btnIdToDialogId = {
            "passwordCredDialogBtnCancel": "passwordCredDialog",
        };
        hideDialog(btnIdToDialogId[e.target.id]);
    };

    function enjectDialogForm(dialogId, formId, cols) {
        var form = $("#" + formId);
        cols.forEach(function(column){
            if (column.dialogHide) {
                return;
            }
            var container = $("<div></div>");
            var label = $("<label for='" + column.id + "'>" + column.name_with_desc + "</label>");
            var type = "text";
            if (column.type == "password") {
                type = "password";
            }
            var input = undefined;
            input = $("<input type='" + type + "' name='" + column.name_with_desc + "' id='" + column.id + "' " + column.required + "/>");
            container.append(label);
            container.append(input);
            form.append(container);
            form.append("<br><br>");
        });
        var container = $('<div style="display: inline;"></div>');
        var saveBtnId = dialogId + "BtnSave";
        var cancelBtnId = dialogId + "BtnCancel";
        container.append($("<input id='" + saveBtnId + "' type='submit' value='Save'/>"));
        container.append($("<input id='" + cancelBtnId + "' type='button' value='Cancel'/>"));
        form.append(container);
        $("#" + cancelBtnId).click(hideDialogHandler);
    };

    function registerBtnClickHandler(did) {
        $("#" + dialogs[did].btnId).click(function(){
            currentAction = "New";
            var table = dialogs[did]["table"];
            $("input#" + table.columns[0].id).prop("readonly", false);
            table.columns.forEach(function(c, j){
                $("input#" + c.id).val("");
            });
            $("input#" + table.columns[0].id).css("background-color", "rgb(255, 255, 255)");
            var dialog = $("#" + did);
            var saveBtnId = did + "BtnSave";
            dialog.text(dialog.text().replace("Edit", "Add"));
            showDialog(did);
        });
    };

    function clearFlag(){
        $("table thead td span").each(function(){
            $(this).removeClass("asque");
            $(this).removeClass("desque");
        });
    };

    function submitForm(formId) {
        var formIdToDialog = {
            "passwordCredForm": dialogs.passwordCredDialog,
        }
        var dialog = formIdToDialog[formId];
        var label = $("label[for='" + dialog.table.columns[0].id + "']");
        label.text(dialog.table.columns[0].name + ": ");
        label.css("color", "black");
        var row = [];
        dialog.table.columns.forEach(function(c, i){
            row[i] = $("#" + c.id).val();
        });
        if (row[0] in dialog.table.dataMap && currentAction == "New") {
            label.text(dialog.table.columns[0].name + ": " + row[0] + " already exists");
            label.css("color", "red");
            return;
        }
        if (currentAction == "Edit") {
            for (var i = 0; i < dialog.table.data.length; i++) {
                if (dialog.table.data[i][0] == row[0]) {
                    dialog.table.data[i] = row;
                    break;
                }
            }
        } else {
            dialog.table.data.push(row);
        }
        dialog.table.dataMap[row[0]] = row;
        console.log("entry: " + dialog.table.dataMap[row[0]]);
        updateTable(dialog.table.id, dialog.table.data, dialog.table.columns);
        hideDialog(dialog.id);
        // $('#passwordBtnAdd').hide();
        clearFlag();
    }

    function submitHandler(event) {
        event.preventDefault();
        event.stopPropagation();
        var formId = event.target.id;
        submitForm(formId);
    }

    function hideColumns(tableId, cols) {
        for (var i = 0; i < cols.length; i++) {
            if (cols[i].hide) {
                $("#" + tableId + " td:nth-child(" + (i + 1) + "),th:nth-child(" + i + ")").hide();
            }
        }
    };

    function updateHeaders(tableId, cols){
        var theadTr = $("#" + tableId + " .tableHead>tr");
        cols.forEach(function(col, i){
            var td = $("<td><span data-idx='" + i + "'>" + col.name+"</span></td>");
            theadTr.append(td);
        });
        var td = $("<td><span data-idx='" + cols.length + "'>Action</span></td>");
        theadTr.append(td);
        hideColumns(tableId, cols);
    };

    function editRow(e) {
        currentAction = "Edit";
        var rowIdAndTableId = e.target.id.split("``");
        var table = tables[rowIdAndTableId[1]];
        var credName = $("input#" + table.columns[0].id);
        credName.prop("readonly", true);
        credName.css("background-color", "#D3D3D3");
        var did = undefined;
        for (var dialogId in dialogs) {
            if (dialogs[dialogId].table.id == table.id) {
                did = dialogId;
                break;
            }
        }
        var dialog = $("#" + did);
        dialog.text(dialog.text().replace("Add", "Edit"));
        showDialog(did);
        table.columns.forEach(function(c, i){
            $("input#" + c.id).val(table.dataMap[rowIdAndTableId[0]][i]);
        });
        return false;
    };

    function deleteRow(e) {
        var rowIdAndTableId = e.target.id.split("``");
        var table = tables[rowIdAndTableId[1]];
        for (var i = 0; i < table.data.length; i++) {
            if (table.data[i][0] == rowIdAndTableId[0]) {
                table.data.splice(i, 1);
                delete table.dataMap[rowIdAndTableId[0]];
                break;
            }
        }
        updateTable(table.id, table.data, table.columns);
        return false;
    };

    function updateTable(tableId, tableData, cols){
        tableLength = tableData.length;
        // console.log("ROW COUNT: " + tableLength);
        if(tableLength >= 1) {
            $('#passwordBtnAdd').hide();
        } else {
            $('#passwordBtnAdd').show();
        }
        if(tableLength > 1) {
            return
        }
        var tbody = $("#" + tableId + " .tableBody");
        tbody.empty();
        tableData.forEach(function(row){
            var tr = $("<tr></tr>");
            row.forEach(function(cell){
                var td = $("<td>" + cell + "</td>");
                tr.append(td);
            });
            var id = row[0] + "``" + tableId;
            var remove_hyperlink_cell= $("<a>", {
                "href": "#",
                "id": id,
                click: deleteRow,
            }).append("Delete");
            var edit_hyperlink_cell= $("<a>", {
                "href": "#",
                "id": id,
                click: editRow,
            }).append("Edit");
            var td = $("<td>").append(remove_hyperlink_cell).append(" | ").append(edit_hyperlink_cell);
            tr.append(td);
            tbody.append(tr);
        });
        hideColumns(tableId, cols);
    };


    function updateCustomizedSettings(settings) {
        if (settings.customized_settings === undefined) {
            return;
        }
        if (settings.customized_settings["autofocus_api_key"]){
            $("#autofocus_api_key_id").val(settings["customized_settings"]["autofocus_api_key"]["password"]);
        }
        if (settings.customized_settings["wildfire_api_key"]){
            $("#wildfire_api_key_id").val(settings["customized_settings"]["wildfire_api_key"]["password"]);
        }
    };

    function getJSONResult() {
        var result = {};
        // Global Settings
        var log_level = $("#log_level_id").val();
        result["global_settings"] = {
            "log_level": log_level,
        }


        // Credential Settings
        var credSettings = {
            "credential_settings": tables.passwordCredTable,
        }
        for (var k in credSettings) {
            result[k] = {};
            var credTable = credSettings[k];
            for (var i = 0; i < credTable.data.length; i++){
                var temp = {};
                credTable.columns.forEach(function(c, j){
                    temp[c.id] = credTable.data[i][j];
                });
                result[k][temp[credTable.columns[0].id]] = temp;
                delete temp[credTable.columns[0].id];
            }
        }

        // Customized Settings
        var check_dict = {true:1, false:0}
        var user_defined_settings = {
            "autofocus_api_key": {
                "type": "password",
                "password": $("#autofocus_api_key_id").val()
            },
            "wildfire_api_key": {
                "type": "password",
                "password": $("#wildfire_api_key_id").val()
            },
        }
        result["customized_settings"] = user_defined_settings;
        return result;
    };

    function appConfigured() {
        $.ajax({
            url: "/en-US/splunkd/__raw/services/apps/local/Splunk_TA_paloalto",
            type: "POST",
            data: {
                "configured": true
            }
        }).done(function() {
            console.log('set configured as true!');
        }).fail(function() {
            console.log('fail to set configured as true!')
        })
    };

    var saving = false;
    $(".my-btn-primary span").html("Save");
    function saveSettings() {
        // var jsonResult = JSON.stringify(getJSONResult());
        $.ajax({
            url:"/en-US/splunkd/__raw/servicesNS/-/Splunk_TA_paloalto/Splunk_TA_paloalto_input_setup/Splunk_TA_paloalto_settings/Splunk_TA_paloalto_settings",
            type: "POST",
            data: {
                "all_settings": JSON.stringify(getJSONResult())
            }
        }).done(function() {
            $('#load_err_banner').hide();
            $('#save_err_banner').hide();
            $('#info_banner').show();
            appConfigured();
        }).fail(function() {
            $('#load_err_banner').hide();
            $('#save_err_banner').show();
            $('#info_banner').hide();
        }).always(function() {
            saving = false;
            $(".my-btn-primary span").html("Save");
        });
    };

    $(".my-btn-primary").click(function(e){
        e.preventDefault();
        if (saving) {
            return;
        }
        saving = true;
        $(".my-btn-primary span").html("Saving");
        saveSettings();
    });
    $(".my-btn-secondary").click(function(){
        window.location = "../../manager/launcher/apps/local";
    });

    // TODO: use ajax to load the settings and render the page
    $.ajax({
        url: "/en-US/splunkd/__raw/servicesNS/-/Splunk_TA_paloalto/Splunk_TA_paloalto_input_setup/Splunk_TA_paloalto_settings/Splunk_TA_paloalto_settings",
        data: {
            "output_mode": "json"
        },
        type: "GET",
        dataType : "json",
    }).done(function(response) {
        var allSettings = null;
        if (response.entry && response.entry.length > 0) {
            allSettings = $.parseJSON(response.entry[0].content.all_settings);
        }
        // console.log(allSettings);
        //parse the data
        updateGlobalSettings(allSettings);
        updateCustomizedSettings(allSettings);
        var passwordCreds = updateCredentialSettings(passwordColumns, allSettings.credential_settings);
        tables = {
            "passwordCredTable": {
                "id": "passwordCredTable",
                "columns": passwordColumns,
                "data": passwordCreds.data,
                "dataMap": passwordCreds.dataMap,
            },
        };
        dialogs = {
            "passwordCredDialog": {
                "id": "passwordCredDialog",
                "btnId": "passwordBtnAdd",
                "formId": "passwordCredForm",
                "table": tables.passwordCredTable,
            },
        };
        for (var dialogId in dialogs) {
            enjectDialogForm(dialogId, dialogs[dialogId].formId, dialogs[dialogId].table.columns);
            registerBtnClickHandler(dialogId);
        }
        for (var tableId in tables) {
            updateHeaders(tableId, tables[tableId].columns);
            hideColumns(tableId, tables[tableId].columns);
            updateTable(tableId, tables[tableId].data, tables[tableId].columns);
        }
        for (var dialogId in dialogs) {
            $("#" + dialogs[dialogId].formId).submit(submitHandler);
            $("#" + dialogs[dialogId].formId + " input").off("keypress").keypress(dialogId, function(e) {
                if (e.which == 13) {
                    $("#" + e.data + "BtnSave").click();
                    return false;
                }
            });
        }
    }).fail(function(xhr, status, response) {
        $('#load_err_banner').show();
        $('#save_err_banner').hide();
        $('#info_banner').hide();
        console.log(status, response);
    });

}); // the end of require