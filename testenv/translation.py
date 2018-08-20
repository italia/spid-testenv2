# coding: utf-8
import re

_c = re.compile


class Libxml2Translator(object):

    _mapping = {
        'PARSER': {
            'ERR_DOCUMENT_END': [
                (_c(r'Extra content at the end of the document'),
                 'Contenuto extra alla fine del documento.'),
            ],
            'ERR_DOCUMENT_EMPTY': [
                (_c(r'Document is empty'), 'Il documento è vuoto.'),
            ]
        },

        'SCHEMASV': {
            'SCHEMAV_CVC_COMPLEX_TYPE_4': [
                (_c(r"Element '(?P<element>.*)': The attribute '(?P<attribute>.*)' is required but missing."),
                 "Elemento '{element}': L'attributo '{attribute}' è mandatorio ma non presente.")
            ],
            'SCHEMAV_CVC_DATATYPE_VALID_1_2_1': [
                (_c(r"Element '(?P<element>.*)', attribute 'ID': '.*' is not a valid value of the atomic type 'xs:ID'."),
                 "Elemento '{element}', attributo 'ID': Il valore dell'attributo 'ID' può iniziare solo con una lettera o con un underscore."),
                (_c(r"Element '(?P<element>.*)', attribute '(?P<attribute>.*)': '(?P<value>.*)' is not a valid value of the atomic type '(?P<type>.*)'."),
                 "Elemento '{element}', attributo '{attribute}': '{value}' non è un valore valido di tipo atomico '{type}'.")
            ],
            'SCHEMAV_CVC_ENUMERATION_VALID': [
                (_c(r"Element '(?P<element>.*)', attribute '(?P<attribute>.*)': \[facet '(?P<facet>.*)'\] The value '(?P<value>.*)' is not an element of the set (?P<set>.*)."),
                 "Elemento '{element}', attributo '{attribute}': [facet '{facet}'] Il valore '{value}' non è un elemento dell'insieme {set}.")
            ]
        }
    }

    def translate_many(self, errors):
        return [
            self.translate(error) for error in errors
        ]

    def translate(self, error):
        message = self._get_replacement_message(error)
        from testenv.validators import ValidationDetail
        return ValidationDetail(
            None, error.line, error.column, error.domain_name,
            error.type_name, message, error.path,
        )

    def _get_replacement_message(self, error):
        try:
            translation = self._search_translation(error)
            return translation or error.message
        except KeyError:
            return error.message

    def _search_translation(self, error):
        regexp_group = self._mapping[error.domain_name][error.type_name]
        for regexp, translation in regexp_group:
            match = re.match(regexp, error.message)
            if match:
                return translation.format(**match.groupdict())
        return None
