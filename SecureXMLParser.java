import javax.xml.parsers.ParserConfigurationException;  // catching unsupported features
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
 
import org.xml.sax.SAXNotRecognizedException;  // catching unknown features
import org.xml.sax.SAXNotSupportedException;  // catching known but unsupported features
import org.xml.sax.XMLReader;
 
...
 
    SAXParserFactory spf = SAXParserFactory.newInstance();
    SAXParser saxParser = spf.newSAXParser();
    XMLReader reader = saxParser.getXMLReader();
 
    try {
      // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
      // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
 
      // Using the SAXParserFactory's setFeature
      spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
      // Using the XMLReader's setFeature
      reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
 
 
      // Xerces 2 only - http://xerces.apache.org/xerces-j/features.html#external-general-entities
      spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
 
      // remaining parser logic
      ...
 
    } catch (ParserConfigurationException e) {
      // Tried an unsupported feature.
 
    } catch (SAXNotRecognizedException e) {
      // Tried an unknown feature.
 
    } catch (SAXNotSupportedException e) {
      // Tried a feature known to the parser but unsupported.
 
    } catch ... {
      
    }
...