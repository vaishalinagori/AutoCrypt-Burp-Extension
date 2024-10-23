from burp import IBurpExtender, IContextMenuFactory, IHttpListener
from java.io import File
from javax.swing import JMenuItem, JFileChooser
import subprocess
import os

# Global variables to store selected encryption and decryption scripts
selected_encrypt_script = None
selected_decrypt_script = None

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("AutoCrypt")
        self.callbacks.registerContextMenuFactory(self)
        self.callbacks.registerHttpListener(self)

    def createMenuItems(self, invocation):
        menu = []
        # Add Encrypt option to context menu
        menu.append(JMenuItem("Encrypt", actionPerformed=lambda x: self.process_request(invocation, "encrypt")))
        # Add Decrypt option to context menu
        menu.append(JMenuItem("Decrypt", actionPerformed=lambda x: self.process_request(invocation, "decrypt")))
        # Option to re-select encryption or decryption script
        menu.append(JMenuItem("Select Encryption Script", actionPerformed=lambda x: self.select_script("encrypt")))
        menu.append(JMenuItem("Select Decryption Script", actionPerformed=lambda x: self.select_script("decrypt")))
        return menu

    def select_script(self, action_type):
        """ Opens file chooser for selecting encryption or decryption script """
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(None)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            global selected_encrypt_script, selected_decrypt_script
            if action_type == "encrypt":
                selected_encrypt_script = file.getAbsolutePath()
                print("Encryption script selected: {}".format(selected_encrypt_script))
            elif action_type == "decrypt":
                selected_decrypt_script = file.getAbsolutePath()
                print("Decryption script selected: {}".format(selected_decrypt_script))

    def process_request(self, invocation, action_type):
        global selected_encrypt_script, selected_decrypt_script

        # Get the selected script based on action type
        if action_type == "encrypt":
            script_path = selected_encrypt_script
        elif action_type == "decrypt":
            script_path = selected_decrypt_script

        # Check if a script has been selected
        if not script_path:
            print("No {} script selected!".format(action_type))
            return

        # Check if the script exists
        if not os.path.exists(script_path):
            print("{} script not found at path: {}".format(action_type.capitalize(), script_path))
            return

        # Extract HTTP request body
        selected_messages = invocation.getSelectedMessages()
        if not selected_messages:
            print("No HTTP request selected.")
            return

        http_request = selected_messages[0]
        request_info = self.helpers.analyzeRequest(http_request)
        request_body = http_request.getRequest()[request_info.getBodyOffset():].tostring()

        if not request_body:
            print("No data found in HTTP request body.")
            return

        try:
            process = None  # Define the process variable
            output = None  # To capture output

            # Provide the HTTP request body as input to the script
            if script_path.endswith(".py"):
                python_cmd = "python3"  # Adjust based on your environment; use "python" or "python2" if needed
                process = subprocess.Popen([python_cmd, script_path],
                                           stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           universal_newlines=True)
                output, error = process.communicate(input=request_body)

            elif script_path.endswith(".java"):
                # Compile and run Java file
                compile_process = subprocess.Popen(["javac", script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                compile_output, compile_error = compile_process.communicate()

                if compile_process.returncode == 0:
                    # Extract the class name (assuming filename matches class name)
                    class_name = os.path.splitext(os.path.basename(script_path))[0]
                    process = subprocess.Popen(["java", class_name],
                                               stdin=subprocess.PIPE,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE,
                                               universal_newlines=True)
                    output, error = process.communicate(input=request_body)
                else:
                    print("Failed to compile Java file:\n{}".format(compile_error))
                    return
            else:
                # Execute non-Python, non-Java scripts directly
                process = subprocess.Popen([script_path],
                                           stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           universal_newlines=True)
                output, error = process.communicate(input=request_body)

            # Output the result of the script execution
            if process and process.returncode == 0:
                print("{} script executed successfully.\nOutput: {}".format(action_type.capitalize(), output))

                # Replace HTTP request body with the output of the script
                new_request = self.replace_request_body(http_request, output)
                http_request.setRequest(new_request)

            else:
                print("{} script failed with error: {}".format(action_type.capitalize(), error))

        except Exception as e:
            print("Failed to execute {} script: {}".format(action_type, str(e)))

    def replace_request_body(self, http_request, new_body):
        """ Replaces the HTTP request body with the provided new body """
        request_info = self.helpers.analyzeRequest(http_request)
        headers = request_info.getHeaders()
        new_request = self.helpers.buildHttpMessage(headers, new_body)
        return new_request
