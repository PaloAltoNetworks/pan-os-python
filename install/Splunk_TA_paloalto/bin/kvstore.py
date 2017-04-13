import json
import splunk
import splunk.rest
import time
import urllib
import urllib2


class KvStoreHandler(object):

    def __init__(self):
        pass
    
    @classmethod
    def create(self, record, record_id, session_key, options, include_ts=False):
        # Caller is responsible for ensuring that the input IS NOT an array.
        uri = '/servicesNS/{owner}/{app}/storage/collections/data/{collection}'.format(**options)
        if record_id:
            record['_key'] = record_id

        if include_ts:
            record['_time'] = time.time()

        response, content = splunk.rest.simpleRequest(uri, sessionKey=session_key, jsonargs=json.dumps(record))
        return response, content

    @classmethod
    def get(self, key, session_key, options):
        '''Issue a simple KV store query by key. If key is empty, all records
        will be returned.'''

        # Check explicitly for None here as a key of 0 is valid, but would be 
        # treated as "False" in a naive expression such as: key or ''
        if key == None:
            key = ''
        uri = '/servicesNS/{owner}/{app}/storage/collections/data/{collection}/{key}'.format(key=key, **options)
        response, content = splunk.rest.simpleRequest(uri, sessionKey=session_key)
        return response, content
    
    @classmethod
    def delete(self, key, session_key, options):
        '''Issue a simple KV store record deletion by key, 
            <tt>if key is not None and len(key) > 0</tt>.'''
        
        response, content = None, None
        
        if key and isinstance(key, basestring):
            uri = '/servicesNS/{owner}/{app}/storage/collections/data/{collection}/{key}'.format(key=key, **options)
            response, content = splunk.rest.simpleRequest(uri, sessionKey=session_key, method="DELETE")
    
        return response, content
    
    @classmethod
    def query(self, json_query, session_key, options, delete=False):
        '''Issue a complex KV store query. The query string is constructed
        from a valid JSON object. <tt>if delete is True and 
        isinstance(json_query, dict) and len(json_query) > 0</tt>, all 
        records returned by this query are deleted.'''
        method="GET"

        if delete and json_query:
            method = "DELETE"
        
        query = urllib2.quote(json.dumps(json_query))
        uri = '/servicesNS/{owner}/{app}/storage/collections/data/{collection}?query={query}'.format(query=query, **options)
        response, content = splunk.rest.simpleRequest(uri, sessionKey=session_key, method=method)
        return response, content

    @classmethod
    def adv_query(self, getargs, url_options, session_key):
        '''Issue a MORE complex KV store query. The query string is constructed
        from a valid JSON object. Additional parameters such as "limit" can be 
        included in the query_options dictionary.
        
        The allowable_params are: 'fields', 'limit', 'skip', 'sort', 'query'
        '''
        
        options = {}

        for k, v in getargs.iteritems():
            if k == 'query':
                options['query'] = json.dumps(v)
            elif k == 'fields':
                if isinstance(v, basestring):
                    options['fields'] = v
                elif isinstance(v, list):
                    options['fields'] = ','.join(v)
                else:
                    raise ValueError('Invalid value for fields parameter in KV store query.')
            elif k in ['limit', 'skip']:
                # May raise ValueError
                options[k] = str(int(v))
            elif k == 'sort':
                # Since sort order can be a bit complex, we just expect the 
                # consumer to construct their own sort string here. 
                if isinstance(v, basestring):
                    options['sort'] = v
                else:
                    raise ValueError('Invalid value for sort parameter in KV store query.')
            else:
                # Invalid parameter is ignored.
                pass

        params = urllib.urlencode(options)
        uri = '/servicesNS/{owner}/{app}/storage/collections/data/{collection}?{params}'.format(params=params, **url_options)
        response, content = splunk.rest.simpleRequest(uri, sessionKey=session_key)
        return response, content

    @classmethod
    def single_update(self, record, record_id, session_key, options, include_ts=False):
        # Caller is responsible for ensuring that the input IS NOT an array.
        uri = '/servicesNS/{owner}/{app}/storage/collections/data/{collection}/{id}'.format(id=record_id, **options)

        if include_ts:
            record['_time'] = time.time()

        response, content = splunk.rest.simpleRequest(uri, sessionKey=session_key, jsonargs=json.dumps(record))
        return response, content

    @classmethod
    def batch_create(self, records, session_key, options, include_ts=False, time_field=None):
        '''Batch save a set of KV store records.
        
        Arguments:
            records     - The list of records.
            session_key - A Splunk session key.
            options     - A dictionary containing the owner, app, and collection for the records.
            include_ts  - If True, include a timestamp in the record.
            time_field   - If not None, assign the timestamp to the field name indicated.
            
        The current time will overwrite any previously existing values in the 
        chosen time field if include_ts is True.

        The caller is responsible for ensuring that the input IS an array.
        '''
        uri = '/servicesNS/{owner}/{app}/storage/collections/data/{collection}/batch_save'.format(**options)
        if not isinstance(records, list):
            records = [records, ]
        
        if not time_field:
            time_field = '_time'
        
        # Make insert time consistent for this batch of records.
        curr = time.time()
        
        if include_ts:
            for record in records:
                record[time_field] = curr

        response, content = splunk.rest.simpleRequest(uri, sessionKey=session_key, jsonargs=json.dumps(records))    
        return response, content
    