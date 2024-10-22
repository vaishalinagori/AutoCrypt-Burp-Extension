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
            elif action_type == "decrypt":
                selected_decrypt_script = file.getAbsolutePath()

    def process_request(self, invocation, action_type):
        global selected_encrypt_script, selected_decrypt_script

        # Get the HTTP request
        request_info = invocation.getSelectedMessages()[0].getRequest()
        request = self.helpers.bytesToString(request_info)

        # Get the selected text
        selected_offset = invocation.getSelectionBounds()
        if selected_offset and selected_offset[0] != selected_offset[1]:
            # If text is selected, use the selected portion
            selected_text = request[selected_offset[0]:selected_offset[1]]
        else:
            # No text selected, so use the entire POST body
            selected_text = self.extract_post_body(request)

        # Determine which script to use
        if action_type == "encrypt" and selected_encrypt_script is not None:
            script_path = selected_encrypt_script
        elif action_type == "decrypt" and selected_decrypt_script is not None:
            script_path = selected_decrypt_script
        else:
            # If no script is selected, prompt user to select a script
            self.select_script(action_type)
            return

        # Run the selected script with the selected value as input
        try:
            result = self.run_script(script_path, selected_text)
            if result:
                # Replace the selected value in the request with the new encrypted or decrypted data
                if selected_offset and selected_offset[0] != selected_offset[1]:
                    # Replace only the selected text
                    new_request = request[:selected_offset[0]] + result + request[selected_offset[1]:]
                else:
                    # Replace the entire POST body
                    new_request = self.replace_post_body(request, result)

                invocation.getSelectedMessages()[0].setRequest(self.helpers.stringToBytes(new_request))
        except Exception as e:
            print("Error running script: {}".format(e))

    def extract_post_body(self, request):
        """ Extracts the POST body from the HTTP request """
        request_info = self.helpers.analyzeRequest(request)
        body_offset = request_info.getBodyOffset()
        return request[body_offset:]

    def replace_post_body(self, request, new_body):
        """ Replaces the POST body in the HTTP request with new_body """
        request_info = self.helpers.analyzeRequest(request)
        headers = request[:request_info.getBodyOffset()]
        return headers + new_body

    def run_script(self, script_path, input_data):
        """ Runs the specified script and passes input_data to it """
        try:
            # Determine the script type by file extension
            if script_path.endswith(".py"):
                command = ["python", script_path]
            elif script_path.endswith(".java"):
                # For Java, compile the file first and then run it
                javac_command = ["javac", script_path]
                javac_process = subprocess.Popen(javac_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                javac_stdout, javac_stderr = javac_process.communicate()
                if javac_process.returncode != 0:
                    raise Exception(javac_stderr.decode())

                # Extract the directory and class name for running the compiled Java class
                script_dir = os.path.dirname(script_path)
                class_name = os.path.basename(script_path).replace(".java", "")

                # Run the Java class from its directory
                command = ["java", "-cp", script_dir, class_name]
            else:
                raise Exception("Unsupported script type")

            # Run the script and pass the input_data
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(input=input_data.encode())

            if process.returncode == 0:
                return stdout.decode()
            else:
                raise Exception(stderr.decode())

        except Exception as e:
            print("Error running script: {}".format(e))
            return None

