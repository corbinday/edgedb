from __future__ import with_statement

import psycopg2
from semantix.lib.caos.backends.data.base import BaseDataBackend
from semantix.lib.caos.backends.meta.pgsql.common import DatabaseConnection, DatabaseTable

from .datasources import EntityLinks, ConceptLink

class EntityTable(DatabaseTable):
    def create(self):
        """
            CREATE TABLE "caos"."entity"(
                id serial NOT NULL,
                concept_id integer NOT NULL,

                PRIMARY KEY (id),
                FOREIGN KEY (concept_id) REFERENCES "caos"."concept"(id)
            )
        """
        super(EntityTable, self).create()

    def insert(self, *dicts, **kwargs):
        """
            INSERT INTO "caos"."entity"(concept_id) (SELECT id FROM caos.concept WHERE name = %(concept)s) RETURNING id
        """
        return super(EntityTable, self).insert(*dicts, **kwargs)


class PathCacheTable(DatabaseTable):
    def create(self):
        """
            CREATE TABLE caos.path_cache (
                id                  serial NOT NULL,

                entity_id           integer NOT NULL,
                parent_entity_id    integer,

                name_attribute      varchar(255),
                concept_name        varchar(255) NOT NULL,

                weight              integer,

                PRIMARY KEY (id),
                UNIQUE(entity_id, parent_entity_id),

                FOREIGN KEY (entity_id) REFERENCES caos.entity(id)
                    ON UPDATE CASCADE ON DELETE CASCADE,

                FOREIGN KEY (parent_entity_id) REFERENCES caos.entity(id)
                    ON UPDATE CASCADE ON DELETE CASCADE
            )
        """
        super(PathCacheTable, self).create()

    def insert(self, *dicts, **kwargs):
        """
            INSERT INTO
                caos.path_cache
                    (entity_id, parent_entity_id, name_attribute, concept_name, weight)

                VALUES(%(entity_id)s, %(parent_entity_id)s,
                       %(name_attribute)s, %(concept_name)s, %(weight)s)
            RETURNING entity_id
        """
        return super(PathCacheTable, self).insert(*dicts, **kwargs)


class DataBackend(BaseDataBackend):
    def __init__(self, connection):
        self.connection = DatabaseConnection(connection)
        self.entity_table = EntityTable(self.connection)
        self.entity_table.create()
        self.path_cache_table = PathCacheTable(self.connection)
        self.path_cache_table.create()

    def get_concept_from_entity(self, id):
        query = """SELECT
                            c.name
                        FROM
                            caos.entity e
                            INNER JOIN caos.concept c ON c.id = e.concept_id
                        WHERE
                            e.id = %d""" % id
        cursor = self.connection.cursor()
        cursor.execute(query)
        result = cursor.fetchone()
        if result is None:
            return None
        else:
            return result[0]

    def load_entity(self, concept, id):
        query = 'SELECT * FROM "caos"."%s_data" WHERE entity_id = %d' % (concept, id)
        cursor = self.connection.cursor()
        cursor.execute(query)
        result = cursor.fetchone()

        if result is not None:
            return dict((k, result[k]) for k in result.keys() if k != 'entity_id')
        else:
            return None

    def store_entity(self, concept, id, attrs):
        with self.connection as cursor:

            if id is not None:
                query = 'UPDATE "caos"."%s_data" SET ' % concept
                query += ','.join(['%s = %%(%s)s' % (a, a) for a in attrs])
                query += ' WHERE entity_id = %d RETURNING entity_id' % id
            else:
                id = self.entity_table.insert({'concept': concept})[0]

                query = 'INSERT INTO "caos"."%s_data"' % concept
                query += '(entity_id, ' + ','.join(['"%s"' % a for a in attrs]) + ')'
                query += 'VALUES(%(entity_id)s, ' + ','.join(['%%(%s)s' % a for a in attrs]) + ') RETURNING entity_id'

            data = dict((k, unicode(attrs[k]) if attrs[k] is not None else None) for k in attrs)
            data['entity_id'] = id

            cursor.execute(query, data)
            id = cursor.fetchone()
            if id is None:
                raise Exception('failed to store entity')

            print
            print '-' * 60
            print 'Merged entity %s[%s][%s]' % \
                    (concept, id[0], (data['name'] if 'name' in data else ''))
            print '-' * 60


        return id[0]

    def load_links(self, this_concept, this_id, other_concepts=None, link_types=None, reverse=False):

        if link_types is not None and not isinstance(link_types, list):
            link_types = [link_types]

        if other_concepts is not None and not isinstance(other_concepts, list):
            other_concepts = [other_concepts]

        if not reverse:
            source_id = this_id
            target_id = None
            source_concepts = [this_concept]
            target_concepts = other_concepts
        else:
            source_id = None
            target_id = this_id
            target_concepts = [this_concept]
            source_concepts = other_concepts

        links = EntityLinks.fetch(source_id=source_id, target_id=target_id,
                                  target_concepts=target_concepts, source_concepts=source_concepts,
                                  link_types=link_types)

        return links


    def store_links(self, concept, id, links):
        rows = []

        with self.connection as cursor:
            for l in links:
                l.target.flush()

                print
                print '-' * 60
                print 'Merging link %s[%s][%s]---{%s}-->%s[%s][%s]' % \
                        (l.source.__class__.name, l.source.id, (l.source.attrs['name'] if 'name' in l.source.attrs else ''),
                         l.link_type,
                         l.target.__class__.name, l.target.id, (l.target.attrs['name'] if 'name' in l.target.attrs else ''))
                print '-' * 60

                # XXX: that's ugly
                sources = [c.name for c in l.source.__class__.__mro__ if hasattr(c, 'name')]
                targets = [c.name for c in l.target.__class__.__mro__ if hasattr(c, 'name')]

                lt = ConceptLink.fetch(source_concepts=sources, target_concepts=targets,
                                       link_type=l.link_type)

                rows.append(cursor.mogrify('(%(source_id)s, %(target_id)s, %(link_type_id)s, %(weight)s)',
                                           {'source_id': l.source.id,
                                            'target_id': l.target.id,
                                            'link_type_id': lt[0]['id'],
                                            'weight': l.weight}))

            if len(rows) > 0:
                cursor.execute("""INSERT INTO caos.entity_map(source_id, target_id, link_type_id, weight)
                                    ((VALUES %s) EXCEPT (SELECT
                                                                *
                                                            FROM
                                                                caos.entity_map
                                                            WHERE
                                                                (source_id, target_id, link_type_id, weight) in (%s)))
                               """ % (",".join(rows), ",".join(rows)))

    def store_path_cache_entry(self, entity, parent_entity_id, weight):
        self.path_cache_table.insert(entity_id=entity.id,
                                 parent_entity_id=parent_entity_id,
                                 name_attribute=unicode(entity.attrs['name']) if 'name' in entity.attrs else None,
                                 concept_name=entity.name,
                                 weight=weight)

    def clear_path_cache(self):
        self.path_cache_table.create()
        with self.connection as cursor:
            cursor.execute('DELETE FROM caos.path_cache')


    def iter(self, concept):
        with self.connection as cursor:
            cursor.execute('''SELECT
                                    id
                                FROM
                                    caos.entity
                                WHERE
                                    concept_id = (SELECT id FROM caos.concept WHERE name = %(concept)s)''',
                            {'concept': concept})

            for row in cursor:
                id = row[0]
                yield id
