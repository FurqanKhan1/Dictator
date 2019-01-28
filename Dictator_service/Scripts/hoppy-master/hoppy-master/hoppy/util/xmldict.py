"""
Convert XML to Python dict.

http://code.activestate.com/recipes/573463/
"""
from xml.dom.minidom import Document

def _xml_to_dict_helper(node):
    node_dict = {}
   
    if node.attributes:
        for index in range(node.attributes.length):
            attribute = node.attributes.item(index)
            node_dict[attribute.nodeName] = attribute.nodeValue
            
    if node.nodeType == node.TEXT_NODE:
        text = node.nodeValue.strip()
        if text:
            if len(node.childNodes) > 1:
                node_dict['text'] = text
            else:
                node_dict = text
    
    for child in node.childNodes:
        # recursively add the element's children
        newitem = _xml_to_dict_helper(child)
        if newitem:
            if node_dict.has_key(child.nodeName):
                # found duplicate nodeName, force a list
                if type(node_dict[child.nodeName]) is type([]):
                    # append to existing list
                    node_dict[child.nodeName].append(newitem)
                else:
                    # convert to list
                    node_dict[child.nodeName] = [node_dict[child.nodeName], newitem]
            else:
                # only one, directly set the dictionary
                if child.nodeType == child.TEXT_NODE:
                    node_dict = newitem
                else:
                    node_dict[child.nodeName] = newitem
    return node_dict
        
def xml_to_dict(root):
    """
    Converts an XML file or ElementTree Element to a dictionary
    """
    if not isinstance(root, Document):
        raise TypeError, 'Expected ElementTree.Element or file path string'

    return _xml_to_dict_helper(root)
